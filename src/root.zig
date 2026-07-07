//! http3_zig — HTTP/3 for Zig, layered above quic_zig and boringssl-zig.
//!
//! ## Concurrency model
//!
//! `http3_zig.Session` and the `Client` / `Server` facades layered on
//! top are **single-threaded, drain-in-batches**. Pin one
//! `Session` to one thread; the public API has no internal locking,
//! atomic counters, or concurrent-safe data structures. Each public
//! operation (open*, send*, drain, close, …) mutates session state
//! directly.
//!
//! The expected usage shape is:
//!
//!   1. Pump packets in / out of the underlying `quic_zig.Connection`.
//!   2. Call `Session.drain(&events)` to emit a batch of typed events.
//!   3. Process events; call back into `Session` to act on them.
//!   4. Free drained events with `session.clearEvents(&events)` or
//!      `http3_zig.clearEvents(allocator, &events)` using the same allocator
//!      the `Session` was constructed with.
//!   5. Repeat.
//!
//! For multi-connection servers, run one `Session` per connection on
//! a single dispatch thread (or one thread per shard, with each shard
//! owning a disjoint set of sessions). Two threads operating on the
//! same `Session` simultaneously is undefined behavior.
//!
//! ## Allocator contract
//!
//! `http3_zig` does not own a global allocator. Every long-lived
//! object takes one explicitly and uses **that same allocator** for
//! its full lifetime. The allocator is not required to be
//! thread-safe — sessions are single-threaded (see above).
//!
//! - `Session.init(allocator, role, *quic.Connection, config)` stores
//!   the allocator. The session uses it for everything it owns:
//!   per-stream `StreamState` (rx buffers, decoders), the QPACK
//!   encoder/decoder dynamic tables and stream state, push-promise
//!   field caches, priority maps, WebTransport per-session flow
//!   state, and the deep-owned bytes attached to each yielded
//!   `Event`. A single long-lived allocator (e.g. `GeneralPurposeAllocator`,
//!   page allocator, or a wrapping arena that lives at least as long
//!   as the session) is the right shape. **Do not** back a `Session`
//!   with an arena that gets `reset()` between drains — the dynamic
//!   tables and per-stream rx buffers persist across calls and a
//!   reset would corrupt them. Per-drain arenas are fine for
//!   *consuming* events, just not for the session itself.
//! - `Client.init(*Session)` and `Server.init(*Session)` are thin
//!   facades — they hold the session pointer and inherit its
//!   allocator. They take no allocator of their own. `Client.init`
//!   does not own the session; `Session.deinit` is still the
//!   caller's responsibility.
//! - `Session.drain(events: *ArrayList(Event))` writes into the
//!   caller-provided list. The list's allocator (which the caller
//!   chose) is independent of the session's; it just stores the
//!   `Event` enum tags. The **bytes inside each event** (header
//!   field name/value pairs, DATA payload slices, DATAGRAM payload,
//!   priority field-value, close-reason, push-promise field section,
//!   WebTransport stream-data) are deep-cloned by the session out of
//!   the session's allocator. The session retains no reference to
//!   them after drain returns; ownership transfers to the caller.
//! - For each yielded event the caller must eventually call
//!   `event.deinit(allocator)`, `session.clearEvents(&events)`, or
//!   `http3_zig.clearEvents(allocator, &events)` using the **session's**
//!   allocator (the one passed to `Session.init`), not the events list's
//!   allocator. A typical pattern:
//!
//!       defer for (events.items) |ev| ev.deinit(session.allocator);
//!       defer events.deinit(events_arena);
//!
//!   `event.deinit` and the batch helpers are no-ops for variants whose
//!   payload is plain scalars (peer_settings, flow_blocked, goaway,
//!   stream_finished, stream_reset, request_rejected, datagram_acked/lost, push_stream,
//!   cancel_push, ignored_unknown_frame, webtransport_stream_opened/
//!   _finished/_reset/_flow_violated, connection_ids_needed). Calling
//!   it on every event is always safe.
//! - `Session.deinit` frees only state still owned by the session:
//!   per-stream buffers, QPACK tables, hash maps, etc. It does **not**
//!   free events that have already been yielded by `drain` —
//!   ownership of those moved to the caller, who is responsible for
//!   freeing each one (or accepting the leak). Drain any pending
//!   events and free them before calling `Session.deinit`.
//! - Trackers (`ResponseTracker`, `RequestTracker`,
//!   `PushedResponseTracker`) take their **own** allocator at
//!   `init`. They hold cloned per-stream lifecycle state (response
//!   headers, accumulated body bytes, trailers) independent of the
//!   session — this allocator can differ from the session's, and the
//!   tracker's `deinit` releases everything it cloned.
//! - The underlying `*quic_zig.Connection` is owned by the embedder.
//!   `Session` borrows it; `Session.deinit` does not free it.

const std = @import("std");
const boringssl = @import("boringssl");
const quic_zig = @import("quic_zig");

pub const protocol = @import("protocol.zig");
pub const settings = @import("settings.zig");
pub const frame = @import("frame.zig");
pub const qpack = @import("qpack/root.zig");
pub const headers = @import("headers.zig");
pub const stream = @import("stream.zig");
pub const priority = @import("priority.zig");
pub const message = @import("message.zig");
pub const datagram = @import("datagram.zig");
pub const capsule = @import("capsule.zig");
pub const errors = @import("errors.zig");
pub const driver = @import("driver.zig");
pub const runner = @import("runner.zig");
pub const observability = @import("observability.zig");
pub const websocket = @import("websocket.zig");
pub const webtransport = @import("webtransport.zig");
pub const masque = @import("masque.zig");
pub const session = @import("session.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");

pub const Session = session.Session;
pub const Event = session.Event;
pub const SessionConfig = session.Config;
pub const SessionProductionOptions = session.ProductionOptions;
pub const SessionBufferedStreamPolicy = session.BufferedStreamPolicy;
pub const ShutdownState = session.ShutdownState;
pub const Client = client.Client;
pub const Server = server.Server;
pub const RequestOptions = client.RequestOptions;
pub const RequestHeadOptions = client.RequestHeadOptions;
pub const RequestWriter = client.RequestWriter;
pub const ResponseState = client.ResponseState;
pub const ResponseReader = client.ResponseReader;
pub const ResponseEvent = client.ResponseEvent;
pub const PushedResponseState = client.PushedResponseState;
pub const PushedResponseReader = client.PushedResponseReader;
pub const WebSocketConnectOptions = client.WebSocketConnectOptions;
pub const WebSocketClientStream = client.WebSocketClientStream;
pub const WebTransportConnectOptions = client.WebTransportConnectOptions;
pub const WebTransportClientStream = client.WebTransportClientStream;
pub const ResponseTracker = client.ResponseTracker;
pub const ResponseTrackerConfig = client.ResponseTrackerConfig;
pub const ResponseTrackerError = client.ResponseTrackerError;
pub const PushedResponseTracker = client.PushedResponseTracker;
pub const PushedResponseTrackerConfig = client.PushedResponseTrackerConfig;
pub const ResponseOptions = server.ResponseOptions;
pub const ResponseHeadOptions = server.ResponseHeadOptions;
pub const ResponseWriter = server.ResponseWriter;
pub const PushOptions = server.PushOptions;
pub const PushHeadOptions = server.PushHeadOptions;
pub const PushPromisePolicy = server.PushPromisePolicy;
pub const PushPromisePolicyError = server.PushPromisePolicyError;
pub const PushPromiseRequestOptions = server.PushPromiseRequestOptions;
pub const PushFromRequestOptions = server.PushFromRequestOptions;
pub const PushFromRequestHeadOptions = server.PushFromRequestHeadOptions;
pub const Push = server.Push;
pub const PushWriter = server.PushWriter;
pub const RequestState = server.RequestState;
pub const RequestReader = server.RequestReader;
pub const RequestEvent = server.RequestEvent;
pub const WebSocketAcceptOptions = server.WebSocketAcceptOptions;
pub const WebSocketServerStream = server.WebSocketServerStream;
pub const WebTransportAcceptOptions = server.WebTransportAcceptOptions;
pub const WebTransportServerStream = server.WebTransportServerStream;
pub const WebTransportCloseSession = webtransport.CloseSession;
pub const WebTransportParsedAvailableProtocols = webtransport.ParsedAvailableProtocols;
pub const WebTransportCapsuleEvent = webtransport.CapsuleEvent;
pub const WebTransportStreamHeader = webtransport.StreamHeader;
pub const WebTransportStreamHeaderDecoded = webtransport.StreamHeaderDecoded;
pub const WebTransportStreamKind = webtransport.StreamKind;
pub const WebTransportStreamOpenedEvent = session.WebTransportStreamOpenedEvent;
pub const WebTransportStreamDataEvent = session.WebTransportStreamDataEvent;
pub const WebTransportStreamFinishedEvent = session.WebTransportStreamFinishedEvent;
pub const WebTransportStreamResetEvent = session.WebTransportStreamResetEvent;
pub const WebTransportFlowViolationEvent = session.WebTransportFlowViolationEvent;
pub const WebTransportFlowViolationKind = session.WebTransportFlowViolationKind;
// `WTSessionFlowState` (mutable per-session flow accounting) is intentionally
// internal — applications only see the read-only snapshot below.
pub const WTSessionFlowSnapshot = session.WTSessionFlowSnapshot;
pub const WebSocketOpcode = websocket.frame.Opcode;
pub const WebSocketFrame = websocket.frame.Frame;
pub const WebSocketOwnedFrame = websocket.frame.OwnedFrame;
pub const WebSocketFrameDecoder = websocket.frame.Decoder;
pub const WebSocketFrameDecodeOptions = websocket.frame.DecodeOptions;
pub const WebSocketFrameEncodeOptions = websocket.frame.EncodeOptions;
pub const WebSocketFrameError = websocket.frame.Error;
pub const WebSocketMessageKind = websocket.message.Kind;
pub const WebSocketMessageEvent = websocket.message.Event;
pub const WebSocketMessageClose = websocket.message.Close;
pub const WebSocketMessageDecoder = websocket.message.Decoder;
pub const WebSocketMessageDecodeOptions = websocket.message.DecodeOptions;
pub const WebSocketMessageError = websocket.message.Error;
pub const ConnectUdpOptions = client.ConnectUdpOptions;
pub const ConnectUdpClientStream = client.ConnectUdpClientStream;
pub const ConnectUdpAcceptOptions = server.ConnectUdpAcceptOptions;
pub const ConnectUdpServerStream = server.ConnectUdpServerStream;
pub const ConnectUdpTarget = masque.ConnectUdpTarget;
pub const OwnedConnectUdpTarget = masque.OwnedConnectUdpTarget;
pub const MasqueContextKind = masque.ContextKind;
pub const MasqueContextIdAllocator = masque.ContextIdAllocator;
pub const MasqueContextPayload = masque.ContextPayload;
pub const MasqueContextRegistry = masque.ContextRegistry;
pub const MasqueCapsuleRegistry = masque.CapsuleRegistry;
pub const MasqueExtensionCapsule = masque.ExtensionCapsule;
pub const MasqueRegisteredCapsuleType = masque.RegisteredCapsuleType;
pub const MasquePendingDatagramBuffer = masque.PendingDatagramBuffer;
pub const MasquePendingDatagramBufferConfig = masque.PendingDatagramBufferConfig;
pub const MasqueBufferedDatagram = masque.BufferedDatagram;
pub const MasqueConnectUdpReceiver = masque.ConnectUdpReceiver;
pub const MasqueDatagramDisposition = masque.DatagramDisposition;
pub const MasqueReceiveDisposition = masque.ReceiveDisposition;
pub const MasqueStreamAbort = masque.StreamAbort;
pub const MasqueAbortReason = masque.AbortReason;
pub const MasqueError = masque.Error;
pub const RequestTracker = server.RequestTracker;
pub const RequestTrackerConfig = server.RequestTrackerConfig;
pub const RequestTrackerError = server.RequestTrackerError;
pub const ConnectionClosedEvent = session.ConnectionClosedEvent;
pub const Settings = settings.Settings;
pub const Frame = frame.Frame;
pub const FieldLine = qpack.FieldLine;
pub const DynamicTable = qpack.DynamicTable;
pub const QpackIndexingPolicy = qpack.IndexingPolicy;
pub const QpackEncoderInstruction = qpack.EncoderInstruction;
pub const QpackDecoderInstruction = qpack.DecoderInstruction;
pub const QpackFieldSectionDecodeOptions = qpack.FieldSectionDecodeOptions;
pub const QpackEncoderState = qpack.QpackEncoderState;
pub const QpackDecoderState = qpack.QpackDecoderState;
pub const Priority = priority.Priority;
pub const PriorityTarget = session.PriorityTarget;
pub const PriorityUpdateEvent = session.PriorityUpdateEvent;
pub const MessageEncoder = message.Encoder;
pub const MessageDecoder = message.Decoder;
pub const DatagramEvent = session.DatagramEvent;
pub const DatagramSendEvent = session.DatagramSendEvent;
pub const PushStreamEvent = session.PushStreamEvent;
pub const CancelPushEvent = session.CancelPushEvent;
pub const PushPolicy = session.PushPolicy;
pub const FlowBlockedEvent = session.FlowBlockedEvent;
pub const FlowBlockedKind = session.FlowBlockedKind;
pub const FlowBlockedSource = session.FlowBlockedSource;
pub const ConnectionIdsNeededEvent = session.ConnectionIdsNeededEvent;
pub const StreamSendState = session.StreamSendState;
pub const Capsule = capsule.Capsule;
pub const CapsuleDecoded = capsule.Decoded;
pub const CapsuleReassembler = capsule.Reassembler;
pub const DatagramContextPayload = datagram.ContextPayload;
pub const TransportEndpoint = driver.Endpoint;
pub const TransportLoopbackOptions = driver.LoopbackOptions;
pub const TransportLoopback = driver.Loopback;
pub const TransportStepStats = driver.StepStats;
pub const ClientRunner = runner.ClientRunner;
pub const ClientRunnerConfig = runner.ClientRunnerConfig;
pub const ClientObservation = runner.ClientObservation;
pub const ServerRunner = runner.ServerRunner;
pub const ServerRunnerConfig = runner.ServerRunnerConfig;
pub const ServerObservation = runner.ServerObservation;
pub const RunnerBatchStats = runner.BatchStats;
pub const KeylogCallback = observability.KeylogCallback;
pub const QuicQlogCallback = observability.QuicQlogCallback;
pub const QuicQlogEvent = observability.QuicQlogEvent;
pub const QuicQlogEventName = observability.QuicQlogEventName;
pub const ObservabilityHooks = observability.Hooks;
pub const TraceEvent = observability.TraceEvent;
pub const TraceEventName = observability.TraceEventName;
pub const TraceCallback = observability.TraceCallback;
pub const Metrics = observability.Metrics;
pub const ErrorScope = errors.Scope;
pub const ErrorSource = errors.Source;
pub const ErrorCategory = errors.Category;
pub const ApplicationError = errors.ApplicationError;
pub const ConnectionError = errors.ConnectionError;
pub const StreamError = errors.StreamError;

/// The package version, single-sourced from `build.zig.zon` through the
/// `build_options` module so it can never drift from the manifest.
pub fn version() []const u8 {
    return @import("build_options").version;
}

/// Releases deep-cloned payload bytes for every drained `Session` event.
/// Pass the allocator used to initialize the session that produced them.
pub fn deinitEvents(allocator: std.mem.Allocator, events: []const Event) void {
    session.deinitEvents(allocator, events);
}

/// Releases drained `Session` event payloads, then clears the caller-owned
/// list while retaining capacity for the next drain.
pub fn clearEvents(allocator: std.mem.Allocator, events: *std.ArrayList(Event)) void {
    session.clearEvents(allocator, events);
}

test {
    _ = boringssl;
    _ = quic_zig;
    _ = protocol;
    _ = settings;
    _ = frame;
    _ = qpack;
    _ = headers;
    _ = stream;
    _ = priority;
    _ = message;
    _ = datagram;
    _ = capsule;
    _ = errors;
    _ = driver;
    _ = runner;
    _ = observability;
    _ = websocket;
    _ = webtransport;
    _ = masque;
    _ = session;
    _ = client;
    _ = server;
}

test "package metadata" {
    // Single-sourced from build.zig.zon; assert it's populated and well-formed
    // rather than pinning a literal that must be bumped in two places.
    const v = version();
    try std.testing.expect(v.len > 0 and std.mem.indexOfScalar(u8, v, '.') != null);
    try std.testing.expectEqualStrings("h3", protocol.alpn_h3);
}
