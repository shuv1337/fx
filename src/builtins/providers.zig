const std = @import("std");

const stream_provider = @import("../core/agent/stream_provider.zig");
const inference_provider = @import("../core/gateway/inference_provider.zig");
const provider_set = @import("../core/gateway/provider_set.zig");
const gateway = @import("gateway.zig");
const direct_providers = @import("direct_providers.zig");
const openai_codex = @import("../gateway/openai_codex.zig");
const openai_codex_models = @import("../gateway/openai_codex_models.zig");
const openai_codex_permission_reviewer = @import("../gateway/openai_codex_permission_reviewer.zig");
const xai_grok = @import("../gateway/xai_grok.zig");
const xai_grok_models = @import("../gateway/xai_grok_models.zig");
const xai_grok_permission_reviewer = @import("../gateway/xai_grok_permission_reviewer.zig");
const provider_catalog = @import("../core/auth/provider_catalog.zig");

const routed_gateway_stream = stream_provider.Provider{
    .stream_fn = streamGatewayOrDirect,
};

pub const native = provider_set.Set{
    .gateway = blk: {
        var bundle = gateway.provider_bundle;
        bundle.agent_stream = routed_gateway_stream;
        break :blk bundle;
    },
    .codex = .{
        .presentation = provider_catalog.find(.codex),
        .auth_strategy = .chatgpt,
        .agent_stream = openai_codex.agent_stream_provider,
        .cli_model_catalog = openai_codex_models.cli_model_catalog_provider,
        .model_catalog = openai_codex_models.model_catalog_provider,
        .permission_reviewer = openai_codex_permission_reviewer.provider,
    },
    .grok = .{
        .presentation = provider_catalog.find(.grok),
        .auth_strategy = .grok,
        .agent_stream = xai_grok.agent_stream_provider,
        .cli_model_catalog = xai_grok_models.cli_model_catalog_provider,
        .model_catalog = xai_grok_models.model_catalog_provider,
        .permission_reviewer = xai_grok_permission_reviewer.provider,
    },
};

fn streamGatewayOrDirect(
    _: ?*anyopaque,
    alloc: std.mem.Allocator,
    request: stream_provider.ModelRequest,
) anyerror!stream_provider.Result {
    return switch (inference_provider.routeForModel(request.model).provider) {
        .vercel_ai_gateway => gateway.agent_stream_provider.stream(alloc, request),
        .anthropic_max, .openai_codex, .xai_direct => direct_providers.agent_stream_provider.stream(alloc, request),
    };
}

test "native provider set preserves upstream bundles and routes qualified Gateway models" {
    try std.testing.expect(native.gateway.agent_stream.?.stream_fn == routed_gateway_stream.stream_fn);
    try std.testing.expect(native.codex.agent_stream.?.stream_fn == openai_codex.agent_stream_provider.stream_fn);
    try std.testing.expect(native.grok.agent_stream.?.stream_fn == xai_grok.agent_stream_provider.stream_fn);
}
