//! Structured HTTP/3 error classification.
//!
//! HTTP/3 error codes are carried as QUIC application error codes. This module
//! gives callers a stable shape for classifying local causes, connection
//! closes, and stream resets without matching on raw integers or `@errorName`.

const std = @import("std");

const protocol = @import("protocol.zig");

pub const Scope = enum {
    connection,
    stream,
    application,
};

pub const Source = enum {
    local,
    peer,
};

pub const Category = enum {
    no_error,
    general,
    internal,
    stream_creation,
    critical_stream,
    frame,
    settings,
    message,
    id,
    request,
    connect,
    qpack,
    transport,
    resource,
    application,
    unknown,
};

pub const ApplicationError = struct {
    code: u64,
    name: []const u8,
    category: Category,
    default_scope: Scope,

    pub fn known(self: ApplicationError) bool {
        return self.category != .unknown;
    }

    pub fn isQpack(self: ApplicationError) bool {
        return self.category == .qpack;
    }

    pub fn isRequestScoped(self: ApplicationError) bool {
        return self.default_scope == .stream and self.category == .request;
    }
};

pub const LocalError = struct {
    cause: anyerror,
    cause_name: []const u8,
    application: ApplicationError,
    scope: Scope,
    category: Category,

    pub fn connection(self: LocalError) ConnectionError {
        return .{
            .source = .local,
            .application = self.application,
            .cause = self.cause,
            .cause_name = self.cause_name,
        };
    }
};

pub const ConnectionError = struct {
    source: Source,
    application: ApplicationError,
    cause: ?anyerror = null,
    cause_name: ?[]const u8 = null,

    pub fn reason(self: ConnectionError) []const u8 {
        return self.cause_name orelse self.application.name;
    }
};

pub const StreamError = struct {
    source: Source,
    stream_id: u64,
    application: ApplicationError,
    final_size: ?u64 = null,
};

pub fn applicationError(code: u64) ApplicationError {
    return switch (code) {
        protocol.ErrorCode.no_error => known(code, "H3_NO_ERROR", .no_error, .application),
        protocol.ErrorCode.general_protocol_error => known(code, "H3_GENERAL_PROTOCOL_ERROR", .general, .connection),
        protocol.ErrorCode.internal_error => known(code, "H3_INTERNAL_ERROR", .internal, .connection),
        protocol.ErrorCode.stream_creation_error => known(code, "H3_STREAM_CREATION_ERROR", .stream_creation, .connection),
        protocol.ErrorCode.closed_critical_stream => known(code, "H3_CLOSED_CRITICAL_STREAM", .critical_stream, .connection),
        protocol.ErrorCode.frame_unexpected => known(code, "H3_FRAME_UNEXPECTED", .frame, .connection),
        protocol.ErrorCode.frame_error => known(code, "H3_FRAME_ERROR", .frame, .connection),
        protocol.ErrorCode.excess_load => known(code, "H3_EXCESSIVE_LOAD", .general, .connection),
        protocol.ErrorCode.id_error => known(code, "H3_ID_ERROR", .id, .connection),
        protocol.ErrorCode.settings_error => known(code, "H3_SETTINGS_ERROR", .settings, .connection),
        protocol.ErrorCode.missing_settings => known(code, "H3_MISSING_SETTINGS", .settings, .connection),
        protocol.ErrorCode.request_rejected => known(code, "H3_REQUEST_REJECTED", .request, .stream),
        protocol.ErrorCode.request_cancelled => known(code, "H3_REQUEST_CANCELLED", .request, .stream),
        protocol.ErrorCode.request_incomplete => known(code, "H3_REQUEST_INCOMPLETE", .request, .stream),
        protocol.ErrorCode.message_error => known(code, "H3_MESSAGE_ERROR", .message, .connection),
        protocol.ErrorCode.connect_error => known(code, "H3_CONNECT_ERROR", .connect, .stream),
        protocol.ErrorCode.version_fallback => known(code, "H3_VERSION_FALLBACK", .general, .connection),
        protocol.ErrorCode.qpack_decompression_failed => known(code, "QPACK_DECOMPRESSION_FAILED", .qpack, .connection),
        protocol.ErrorCode.qpack_encoder_stream_error => known(code, "QPACK_ENCODER_STREAM_ERROR", .qpack, .connection),
        protocol.ErrorCode.qpack_decoder_stream_error => known(code, "QPACK_DECODER_STREAM_ERROR", .qpack, .connection),
        else => .{
            .code = code,
            .name = "UNKNOWN_APPLICATION_ERROR",
            .category = .unknown,
            .default_scope = .application,
        },
    };
}

pub fn classify(err: anyerror) LocalError {
    const app = applicationError(codeForError(err));
    return .{
        .cause = err,
        .cause_name = @errorName(err),
        .application = app,
        .scope = scopeForError(err, app),
        .category = categoryForError(err, app),
    };
}

pub fn codeForError(err: anyerror) u64 {
    return switch (err) {
        error.MissingSettings => protocol.ErrorCode.missing_settings,
        error.DuplicateSettings,
        error.DuplicateSetting,
        error.ReservedSetting,
        error.InvalidSettingValue,
        => protocol.ErrorCode.settings_error,
        error.FrameUnexpected => protocol.ErrorCode.frame_unexpected,
        error.InvalidFramePayload,
        error.InsufficientBytes,
        error.ValueTooLarge,
        error.InvalidLength,
        => protocol.ErrorCode.frame_error,
        error.HeaderSectionTooLarge,
        error.DataBeforeHeaders,
        error.DuplicateHeaders,
        error.DataAfterTrailers,
        error.UnexpectedPushPromise,
        error.MissingHeaders,
        error.EmptyFieldName,
        error.UppercaseFieldName,
        error.PseudoHeaderAfterRegular,
        error.DuplicatePseudoHeader,
        error.MissingPseudoHeader,
        error.InvalidPseudoHeader,
        error.ConnectionSpecificField,
        => protocol.ErrorCode.message_error,
        error.HuffmanUnsupported,
        error.InvalidHuffmanCode,
        error.InvalidHuffmanPadding,
        error.HuffmanPaddingTooLong,
        error.HuffmanEos,
        error.DynamicTableUnsupported,
        error.UnsupportedRepresentation,
        error.MalformedFieldSection,
        error.InvalidStaticIndex,
        error.InvalidDynamicIndex,
        error.EntryTooLarge,
        error.CapacityTooLarge,
        error.InvalidRequiredInsertCount,
        error.RequiredInsertCountTooLarge,
        error.RequiredInsertCountNotReady,
        error.BlockedStreamLimitExceeded,
        => protocol.ErrorCode.qpack_decompression_failed,
        error.MalformedEncoderInstruction => protocol.ErrorCode.qpack_encoder_stream_error,
        error.MalformedDecoderInstruction,
        error.InsertCountIncrementZero,
        error.UnexpectedSectionAcknowledgment,
        error.KnownReceivedCountTooHigh,
        => protocol.ErrorCode.qpack_decoder_stream_error,
        error.ClosedCriticalStream => protocol.ErrorCode.closed_critical_stream,
        error.CriticalStreamAlreadyOpen,
        error.QpackStreamsAlreadyOpen,
        error.UnexpectedStream,
        error.StreamAlreadyOpen,
        error.StreamNotFound,
        error.StreamClosed,
        => protocol.ErrorCode.stream_creation_error,
        error.InvalidGoawayId => protocol.ErrorCode.id_error,
        error.RequestBlockedByGoaway => protocol.ErrorCode.request_rejected,
        error.OutOfMemory,
        error.BufferTooSmall,
        error.WriteStalled,
        error.InsertCountOverflow,
        error.ReferenceCountOverflow,
        error.InvalidRole,
        error.MissingStream,
        error.WrongMessageKind,
        => protocol.ErrorCode.internal_error,
        else => protocol.ErrorCode.general_protocol_error,
    };
}

pub fn localConnectionError(err: anyerror) ConnectionError {
    return classify(err).connection();
}

pub fn localConnectionCode(code: u64) ConnectionError {
    return .{
        .source = .local,
        .application = applicationError(code),
    };
}

pub fn peerConnectionError(code: u64) ConnectionError {
    return .{
        .source = .peer,
        .application = applicationError(code),
    };
}

pub fn localStreamError(stream_id: u64, code: u64, final_size: ?u64) StreamError {
    return .{
        .source = .local,
        .stream_id = stream_id,
        .application = applicationError(code),
        .final_size = final_size,
    };
}

pub fn peerStreamError(stream_id: u64, code: u64, final_size: ?u64) StreamError {
    return .{
        .source = .peer,
        .stream_id = stream_id,
        .application = applicationError(code),
        .final_size = final_size,
    };
}

fn known(code: u64, name: []const u8, category: Category, default_scope: Scope) ApplicationError {
    return .{
        .code = code,
        .name = name,
        .category = category,
        .default_scope = default_scope,
    };
}

fn scopeForError(err: anyerror, app: ApplicationError) Scope {
    return switch (err) {
        error.RequestBlockedByGoaway => .stream,
        else => app.default_scope,
    };
}

fn categoryForError(err: anyerror, app: ApplicationError) Category {
    return switch (err) {
        error.OutOfMemory => .resource,
        error.HandshakeFailed,
        error.PeerAlerted,
        error.UnsupportedCipherSuite,
        error.InboxOverflow,
        error.PeerDcidNotSet,
        error.PathLimitExceeded,
        => .transport,
        else => app.category,
    };
}

test "application error code classification names HTTP/3 and QPACK codes" {
    const rejected = applicationError(protocol.ErrorCode.request_rejected);
    try std.testing.expectEqualStrings("H3_REQUEST_REJECTED", rejected.name);
    try std.testing.expectEqual(Category.request, rejected.category);
    try std.testing.expectEqual(Scope.stream, rejected.default_scope);
    try std.testing.expect(rejected.isRequestScoped());

    const qpack = applicationError(protocol.ErrorCode.qpack_decompression_failed);
    try std.testing.expectEqualStrings("QPACK_DECOMPRESSION_FAILED", qpack.name);
    try std.testing.expect(qpack.isQpack());

    const unknown = applicationError(0xface);
    try std.testing.expect(!unknown.known());
    try std.testing.expectEqual(Scope.application, unknown.default_scope);
}

test "local causes map to close codes and cause categories" {
    const settings = classify(error.DuplicateSetting);
    try std.testing.expectEqual(protocol.ErrorCode.settings_error, settings.application.code);
    try std.testing.expectEqual(Category.settings, settings.category);
    try std.testing.expectEqual(Scope.connection, settings.scope);

    const headers = classify(error.ConnectionSpecificField);
    try std.testing.expectEqual(protocol.ErrorCode.message_error, headers.application.code);
    try std.testing.expectEqual(Category.message, headers.category);

    const oom = classify(error.OutOfMemory);
    try std.testing.expectEqual(protocol.ErrorCode.internal_error, oom.application.code);
    try std.testing.expectEqual(Category.resource, oom.category);
}
