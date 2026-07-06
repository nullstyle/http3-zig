const std = @import("std");
const http3_zig = @import("http3_zig");

test "public API smoke: stable embedding surface compiles" {
    const H = http3_zig;

    comptime {
        // Session core and production config.
        _ = H.Session;
        _ = H.Session.init;
        _ = H.Session.deinit;
        _ = H.Session.start;
        _ = H.Session.drain;
        _ = H.Session.close;
        _ = H.Session.openRequest;
        _ = H.Session.sendGoaway;
        _ = H.Session.stopSending;
        _ = H.Session.resetStream;
        _ = H.Session.finishStream;
        _ = H.Session.streamSendState;
        _ = H.SessionConfig;
        _ = H.SessionConfig.production;
        _ = H.SessionProductionOptions;
        _ = H.SessionBufferedStreamPolicy;

        // Client/server facades, runners, and trackers.
        _ = H.Client;
        _ = H.Client.init;
        _ = H.Client.request;
        _ = H.Client.startRequest;
        _ = H.Client.classify;
        _ = H.ClientRunner;
        _ = H.ClientRunner.init;
        _ = H.ClientRunner.observeBatch;
        _ = H.Server;
        _ = H.Server.init;
        _ = H.Server.respond;
        _ = H.Server.push;
        _ = H.Server.classify;
        _ = H.ServerRunner;
        _ = H.ServerRunner.init;
        _ = H.ServerRunner.observeBatch;
        _ = H.RequestOptions;
        _ = H.RequestHeadOptions;
        _ = H.ResponseOptions;
        _ = H.ResponseHeadOptions;
        _ = H.PushOptions;
        _ = H.PushHeadOptions;
        _ = H.RequestWriter;
        _ = H.ResponseWriter;
        _ = H.PushWriter;
        _ = H.RequestReader;
        _ = H.ResponseReader;
        _ = H.PushedResponseReader;
        _ = H.RequestTracker;
        _ = H.RequestTracker.initWithConfig;
        _ = H.ResponseTracker;
        _ = H.ResponseTracker.initWithConfig;
        _ = H.PushedResponseTracker;
        _ = H.PushedResponseTracker.initWithConfig;

        // Transport-driving helpers.
        _ = H.TransportEndpoint;
        _ = H.TransportEndpoint.withSession;
        _ = H.TransportEndpoint.drainSession;
        _ = H.TransportEndpoint.flush;
        _ = H.TransportEndpoint.handle;
        _ = H.TransportEndpoint.tick;
        _ = H.TransportLoopback;
        _ = H.TransportStepStats;

        // Extension facades.
        _ = H.WebSocketConnectOptions;
        _ = H.WebSocketAcceptOptions;
        _ = H.WebSocketClientStream;
        _ = H.WebSocketServerStream;
        _ = H.WebTransportConnectOptions;
        _ = H.WebTransportAcceptOptions;
        _ = H.WebTransportClientStream;
        _ = H.WebTransportClientStream.sendDatagram;
        _ = H.WebTransportClientStream.writeStream;
        _ = H.WebTransportClientStream.finishStream;
        _ = H.WebTransportClientStream.sendCapsule;
        _ = H.WebTransportClientStream.forwardCapsuleTo;
        _ = H.WebTransportClientStream.close;
        _ = H.WebTransportServerStream;
        _ = H.WebTransportServerStream.sendDatagram;
        _ = H.WebTransportServerStream.writeStream;
        _ = H.WebTransportServerStream.finishStream;
        _ = H.WebTransportServerStream.sendCapsule;
        _ = H.WebTransportServerStream.forwardCapsuleTo;
        _ = H.WebTransportServerStream.close;
        _ = H.ConnectUdpOptions;
        _ = H.ConnectUdpAcceptOptions;
        _ = H.ConnectUdpClientStream;
        _ = H.ConnectUdpServerStream;

        // Events, errors, observability, and key codec re-exports.
        _ = H.session.Event;
        _ = H.DatagramEvent;
        _ = H.DatagramSendEvent;
        _ = H.FlowBlockedEvent;
        _ = H.FlowBlockedKind;
        _ = H.ConnectionClosedEvent;
        _ = H.ConnectionIdsNeededEvent;
        _ = H.WebTransportStreamOpenedEvent;
        _ = H.WebTransportStreamDataEvent;
        _ = H.WebTransportFlowViolationEvent;
        _ = H.ApplicationError;
        _ = H.ConnectionError;
        _ = H.StreamError;
        _ = H.ErrorScope;
        _ = H.ErrorSource;
        _ = H.ErrorCategory;
        _ = H.ObservabilityHooks;
        _ = H.TraceCallback;
        _ = H.TraceEvent;
        _ = H.Metrics;
        _ = H.Settings;
        _ = H.Frame;
        _ = H.FieldLine;
        _ = H.MessageEncoder;
        _ = H.MessageDecoder;
        _ = H.Capsule;
        _ = H.CapsuleReassembler;
        _ = H.DatagramContextPayload;
        _ = H.QpackEncoderState;
        _ = H.QpackDecoderState;
        _ = H.QpackIndexingPolicy;
    }

    const production = H.SessionConfig.production(.{});
    try std.testing.expect(production.max_field_section_size != null);
    try std.testing.expectEqualStrings("h3", H.protocol.alpn_h3);
    try std.testing.expect(std.mem.indexOfScalar(u8, H.version(), '.') != null);
}
