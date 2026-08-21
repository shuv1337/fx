const std = @import("std");
const host = @import("../hosts/host.zig");
const io_mod = @import("../shared/io.zig");
const login_flow = @import("login_flow.zig");
const oauth_transport = @import("oauth_transport.zig");
const provider_oauth = @import("provider_oauth.zig");

const Allocator = std.mem.Allocator;

pub const Snapshot = struct {
    provider: ?provider_oauth.Provider = null,
    state: login_flow.SignInState = .idle,
    authorization_url: []const u8 = "",
    user_code: ?[]const u8 = null,
};

pub const Transition = union(enum) {
    none,
    succeeded: provider_oauth.Provider,
    failed: anyerror,
    cancelled,
};

pub const Runtime = struct {
    const Self = @This();

    mutex: std.Io.Mutex = .init,
    thread: ?std.Thread = null,
    cancel_requested: std.atomic.Value(bool) = .init(false),
    worker_finished: std.atomic.Value(bool) = .init(false),
    progress_changed: std.atomic.Value(bool) = .init(false),
    commit_started: bool = false,
    state: login_flow.SignInState = .idle,
    provider: ?provider_oauth.Provider = null,
    authorization_url: ?[]u8 = null,
    user_code: ?[]u8 = null,
    failure: ?anyerror = null,
    transport: oauth_transport.Provider = oauth_transport.unavailable_provider,
    url_opener: host.UrlOpener = host.unavailable_url_opener,
    browser_entropy: [48]u8 = undefined,

    pub fn start(
        self: *Self,
        alloc: Allocator,
        transport: oauth_transport.Provider,
        url_opener: host.UrlOpener,
        provider: provider_oauth.Provider,
    ) !bool {
        var browser_entropy: [48]u8 = undefined;
        if (provider != .xai) try io_mod.getIo().randomSecure(&browser_entropy);

        self.reapFinishedWorker();
        self.mutex.lockUncancelable(io_mod.getIo());
        if (self.thread != null or self.state == .polling) {
            self.mutex.unlock(io_mod.getIo());
            return false;
        }
        self.clearAuthorizationLocked(alloc);
        self.cancel_requested.store(false, .seq_cst);
        self.worker_finished.store(false, .seq_cst);
        self.progress_changed.store(false, .seq_cst);
        self.commit_started = false;
        self.state = .polling;
        self.provider = provider;
        self.failure = null;
        self.transport = transport;
        self.url_opener = url_opener;
        if (provider != .xai) self.browser_entropy = browser_entropy;
        self.mutex.unlock(io_mod.getIo());

        self.thread = std.Thread.spawn(.{}, workerMain, .{ self, alloc }) catch |err| {
            self.mutex.lockUncancelable(io_mod.getIo());
            self.state = .idle;
            self.provider = null;
            self.mutex.unlock(io_mod.getIo());
            return err;
        };
        return true;
    }

    pub fn cancel(self: *Self, alloc: Allocator) bool {
        self.mutex.lockUncancelable(io_mod.getIo());
        const cancelled = self.state == .polling and !self.commit_started;
        if (cancelled) self.cancel_requested.store(true, .seq_cst);
        if (cancelled) self.state = .cancelled;
        if (cancelled) self.clearAuthorizationLocked(alloc);
        self.mutex.unlock(io_mod.getIo());
        return cancelled;
    }

    pub fn deinit(self: *Self, alloc: Allocator) void {
        _ = self.cancel(alloc);
        const thread = self.thread;
        self.thread = null;
        if (thread) |handle| handle.join();
        self.mutex.lockUncancelable(io_mod.getIo());
        self.clearAuthorizationLocked(alloc);
        self.state = .idle;
        self.provider = null;
        self.failure = null;
        self.mutex.unlock(io_mod.getIo());
    }

    pub fn snapshot(self: *const Self) Snapshot {
        const mutable = @constCast(self);
        mutable.mutex.lockUncancelable(io_mod.getIo());
        defer mutable.mutex.unlock(io_mod.getIo());
        return .{
            .provider = self.provider,
            .state = self.state,
            .authorization_url = self.authorization_url orelse "",
            .user_code = self.user_code,
        };
    }

    pub fn browserUrlAlloc(self: *Self, alloc: Allocator) !?[]u8 {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        const url = self.authorization_url orelse return null;
        return try alloc.dupe(u8, url);
    }

    pub fn takeProgressChanged(self: *Self) bool {
        return self.progress_changed.swap(false, .seq_cst);
    }

    pub fn commitInFlight(self: *Self) bool {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        return self.state == .polling and self.commit_started;
    }

    pub fn pollTransition(self: *Self, alloc: Allocator) Transition {
        self.mutex.lockUncancelable(io_mod.getIo());
        const terminal = self.worker_finished.load(.seq_cst) and switch (self.state) {
            .succeeded, .failed, .cancelled => true,
            .idle, .polling => false,
        };
        const thread = if (terminal) self.thread else null;
        if (terminal) self.thread = null;
        self.mutex.unlock(io_mod.getIo());
        if (!terminal) return .none;

        if (thread) |handle| handle.join();

        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        const state = self.state;
        const provider = self.provider;
        const failure = self.failure;
        self.state = .idle;
        self.failure = null;
        self.clearAuthorizationLocked(alloc);
        return switch (state) {
            .succeeded => if (provider) |value| .{ .succeeded = value } else .{ .failed = error.LoginCompletionMissing },
            .failed => .{ .failed = failure orelse error.OAuthRequestFailed },
            .cancelled => .cancelled,
            .idle, .polling => .none,
        };
    }

    fn workerMain(self: *Self, alloc: Allocator) void {
        defer self.worker_finished.store(true, .seq_cst);
        const provider = self.provider orelse return;
        var callback_context = CallbackContext{ .runtime = self, .alloc = alloc };
        const method: provider_oauth.LoginMethod = switch (provider) {
            .anthropic, .openai_codex => .browser,
            .xai => .device_code,
        };
        const observer = provider_oauth.LoginObserver{
            .context = &callback_context,
            .observe_fn = observeAuthorization,
            .begin_commit_fn = beginCommit,
        };
        const cancellation = provider_oauth.LoginCancellation{ .context = &callback_context, .is_cancelled_fn = cancellationRequested };
        const result = if (provider == .xai)
            provider_oauth.runLoginObserved(
                alloc,
                self.transport,
                self.url_opener,
                provider,
                method,
                observer,
                cancellation,
            )
        else
            provider_oauth.runLoginObservedPrepared(
                alloc,
                self.transport,
                self.url_opener,
                provider,
                method,
                observer,
                cancellation,
                self.browser_entropy,
            );
        result catch |err| {
            self.publishFailure(err);
            return;
        };

        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        self.state = if (self.cancel_requested.load(.seq_cst)) .cancelled else .succeeded;
    }

    fn observeAuthorization(raw: ?*anyopaque, authorization: provider_oauth.Authorization) !void {
        const context: *CallbackContext = @ptrCast(@alignCast(raw.?));
        const self = context.runtime;
        const alloc = context.alloc;
        const url = try alloc.dupe(u8, authorization.url);
        errdefer alloc.free(url);
        const code = if (authorization.user_code) |value| try alloc.dupe(u8, value) else null;

        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        std.debug.assert(self.authorization_url == null and self.user_code == null);
        self.authorization_url = url;
        self.user_code = code;
        self.progress_changed.store(true, .seq_cst);
    }

    fn cancellationRequested(raw: ?*anyopaque) bool {
        const context: *CallbackContext = @ptrCast(@alignCast(raw.?));
        return context.runtime.cancel_requested.load(.seq_cst);
    }

    fn beginCommit(raw: ?*anyopaque) !void {
        const context: *CallbackContext = @ptrCast(@alignCast(raw.?));
        const self = context.runtime;
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        if (self.cancel_requested.load(.seq_cst)) return error.LoginCancelled;
        self.commit_started = true;
    }

    fn publishFailure(self: *Self, err: anyerror) void {
        self.mutex.lockUncancelable(io_mod.getIo());
        defer self.mutex.unlock(io_mod.getIo());
        if (err == error.LoginCancelled or self.cancel_requested.load(.seq_cst)) {
            self.state = .cancelled;
            return;
        }
        self.failure = err;
        self.state = .failed;
    }

    fn clearAuthorizationLocked(self: *Self, alloc: Allocator) void {
        if (self.authorization_url) |url| alloc.free(url);
        if (self.user_code) |code| alloc.free(code);
        self.authorization_url = null;
        self.user_code = null;
    }

    fn reapFinishedWorker(self: *Self) void {
        if (!self.worker_finished.load(.seq_cst)) return;
        self.mutex.lockUncancelable(io_mod.getIo());
        const thread = self.thread;
        self.thread = null;
        self.state = .idle;
        self.provider = null;
        self.failure = null;
        self.mutex.unlock(io_mod.getIo());
        if (thread) |handle| handle.join();
    }
};

const CallbackContext = struct {
    runtime: *Runtime,
    alloc: Allocator,
};

test "provider login progress publishes an owned authorization snapshot once" {
    const alloc = std.testing.allocator;
    var runtime: Runtime = .{};
    defer runtime.deinit(alloc);
    runtime.provider = .xai;
    var context = CallbackContext{ .runtime = &runtime, .alloc = alloc };

    try Runtime.observeAuthorization(&context, .{
        .url = "https://auth.example.test/device",
        .user_code = "TEST-CODE",
    });

    const snapshot = runtime.snapshot();
    try std.testing.expectEqual(provider_oauth.Provider.xai, snapshot.provider.?);
    try std.testing.expectEqualStrings("https://auth.example.test/device", snapshot.authorization_url);
    try std.testing.expectEqualStrings("TEST-CODE", snapshot.user_code.?);
    try std.testing.expect(runtime.takeProgressChanged());
    try std.testing.expect(!runtime.takeProgressChanged());
}

test "provider login cancellation and persistence commit are mutually exclusive" {
    const alloc = std.testing.allocator;

    var cancelled: Runtime = .{};
    defer cancelled.deinit(alloc);
    cancelled.state = .polling;
    var cancelled_context = CallbackContext{ .runtime = &cancelled, .alloc = alloc };
    try std.testing.expect(cancelled.cancel(alloc));
    try std.testing.expectError(error.LoginCancelled, Runtime.beginCommit(&cancelled_context));

    var committed: Runtime = .{};
    defer committed.deinit(alloc);
    committed.state = .polling;
    var committed_context = CallbackContext{ .runtime = &committed, .alloc = alloc };
    try Runtime.beginCommit(&committed_context);
    try std.testing.expect(!committed.cancel(alloc));
    try std.testing.expectEqual(login_flow.SignInState.polling, committed.state);
}
