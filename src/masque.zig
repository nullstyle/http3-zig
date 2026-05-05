//! MASQUE-style protocol helpers over Extended CONNECT and HTTP Datagrams.
//!
//! The first concrete protocol covered here is CONNECT-UDP. The helpers stay
//! transport-free: client/server facades open the CONNECT stream, while this
//! module owns request classification, target path construction, and the
//! Context ID 0 UDP payload shape used by CONNECT-UDP datagrams and capsules.

const std = @import("std");

const capsule_mod = @import("capsule.zig");
const datagram_mod = @import("datagram.zig");
const protocol = @import("protocol.zig");
const qpack = @import("qpack/root.zig");

pub const connect_udp_protocol = "connect-udp";
pub const default_connect_udp_path_prefix = "/.well-known/masque/udp";
pub const capsule_protocol_header = "capsule-protocol";
pub const capsule_protocol_value = "?1";
pub const udp_context_id: u64 = 0;
pub const max_udp_payload_len: usize = 65527;
pub const max_registered_contexts: usize = 16;
pub const connect_udp_abort_code = protocol.ErrorCode.connect_error;

pub const Error = datagram_mod.Error || std.mem.Allocator.Error || error{
    BufferTooSmall,
    CannotUnregisterDefaultContext,
    ContextBufferFull,
    ContextAlreadyRegistered,
    ContextLimitExceeded,
    InvalidContextRegistration,
    InvalidConnectUdpPath,
    InvalidConnectUdpTarget,
    InvalidAcceptStatus,
    NotConnectUdp,
    UdpPayloadTooLarge,
    UnexpectedContext,
    UnknownContext,
};

pub const ConnectUdpTarget = struct {
    host: []const u8,
    port: u16,
};

pub const OwnedConnectUdpTarget = struct {
    host: []u8,
    port: u16,

    pub fn deinit(self: OwnedConnectUdpTarget, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn borrowed(self: *const OwnedConnectUdpTarget) ConnectUdpTarget {
        return .{
            .host = self.host,
            .port = self.port,
        };
    }
};

pub const ConnectUdpOptions = struct {
    scheme: []const u8 = "https",
    authority: []const u8 = "",
    target_host: []const u8,
    target_port: u16,
    path_prefix: []const u8 = default_connect_udp_path_prefix,
    headers: []const qpack.FieldLine = &.{},
    capsule_protocol: bool = true,
};

pub const AcceptOptions = struct {
    status: []const u8 = "200",
    headers: []const qpack.FieldLine = &.{},
    capsule_protocol: bool = true,
};

pub const ContextKind = enum {
    connect_udp,
    extension,
};

pub const ContextIdAllocator = enum {
    client,
    proxy,
};

pub const RegisteredContext = struct {
    context_id: u64,
    kind: ContextKind,
};

pub const ContextPayload = struct {
    context_id: u64,
    kind: ContextKind,
    payload: []const u8,

    pub fn raw(self: ContextPayload) datagram_mod.ContextPayload {
        return .{
            .context_id = self.context_id,
            .payload = self.payload,
        };
    }
};

pub const AbortReason = enum {
    malformed_context,
    udp_payload_too_large,
    unexpected_context,
    local_failure,
};

pub const StreamAbort = struct {
    error_code: u64,
    reason: AbortReason,
    cause: ?anyerror = null,
};

pub const DatagramDisposition = union(enum) {
    udp_payload: []const u8,
    extension_payload: ContextPayload,
    unknown_context: datagram_mod.ContextPayload,
    abort_stream: StreamAbort,

    pub fn streamAbort(self: DatagramDisposition) ?StreamAbort {
        return switch (self) {
            .abort_stream => |abort| abort,
            else => null,
        };
    }
};

pub const ReceiveDisposition = union(enum) {
    udp_payload: []const u8,
    extension_payload: ContextPayload,
    unknown_context: datagram_mod.ContextPayload,
    ignored_capsule_type: u64,
    abort_stream: StreamAbort,

    pub fn streamAbort(self: ReceiveDisposition) ?StreamAbort {
        return switch (self) {
            .abort_stream => |abort| abort,
            else => null,
        };
    }

    pub fn canSilentlyDrop(self: ReceiveDisposition) bool {
        return switch (self) {
            .unknown_context, .ignored_capsule_type => true,
            else => false,
        };
    }
};

pub const ConnectUdpReceiver = struct {
    registry: ContextRegistry = ContextRegistry.init(),

    pub fn init() ConnectUdpReceiver {
        return .{};
    }

    pub fn contextRegistry(self: *ConnectUdpReceiver) *ContextRegistry {
        return &self.registry;
    }

    pub fn registerExtension(self: *ConnectUdpReceiver, context_id: u64) Error!void {
        try self.registry.registerExtension(context_id);
    }

    pub fn unregister(self: *ConnectUdpReceiver, context_id: u64) Error!void {
        try self.registry.unregister(context_id);
    }

    pub fn classifyDatagramPayload(self: *const ConnectUdpReceiver, payload: []const u8) ReceiveDisposition {
        return receiveDispositionFromDatagram(self.registry.classifyDatagramPayload(payload));
    }

    pub fn classifyCapsule(self: *const ConnectUdpReceiver, capsule: capsule_mod.Capsule) ReceiveDisposition {
        if (!capsule.isDatagram()) return .{ .ignored_capsule_type = capsule.capsule_type };
        return self.classifyDatagramPayload(capsule.value);
    }
};

pub const PendingDatagramBufferConfig = struct {
    max_datagrams: usize = 16,
    max_payload_bytes: usize = 64 * 1024,
};

pub const BufferedDatagram = struct {
    context_id: u64,
    payload: []u8,

    pub fn deinit(self: BufferedDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }

    pub fn context(self: BufferedDatagram, kind: ContextKind) ContextPayload {
        return .{
            .context_id = self.context_id,
            .kind = kind,
            .payload = self.payload,
        };
    }

    pub fn raw(self: BufferedDatagram) datagram_mod.ContextPayload {
        return .{
            .context_id = self.context_id,
            .payload = self.payload,
        };
    }
};

pub fn freeBufferedDatagrams(allocator: std.mem.Allocator, datagrams: []BufferedDatagram) void {
    for (datagrams) |datagram| datagram.deinit(allocator);
}

pub const PendingDatagramBuffer = struct {
    allocator: std.mem.Allocator,
    config: PendingDatagramBufferConfig = .{},
    datagrams: std.ArrayList(BufferedDatagram) = .empty,
    payload_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator) PendingDatagramBuffer {
        return .{ .allocator = allocator };
    }

    pub fn initWithConfig(
        allocator: std.mem.Allocator,
        config: PendingDatagramBufferConfig,
    ) PendingDatagramBuffer {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *PendingDatagramBuffer) void {
        freeBufferedDatagrams(self.allocator, self.datagrams.items);
        self.datagrams.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const PendingDatagramBuffer) usize {
        return self.datagrams.items.len;
    }

    pub fn bufferedPayloadBytes(self: *const PendingDatagramBuffer) usize {
        return self.payload_bytes;
    }

    pub fn bufferUnknown(self: *PendingDatagramBuffer, context: datagram_mod.ContextPayload) Error!void {
        if (context.context_id == udp_context_id) return Error.UnexpectedContext;
        try self.reserve(context.payload.len);
        const payload = try self.allocator.dupe(u8, context.payload);
        errdefer self.allocator.free(payload);
        try self.datagrams.append(self.allocator, .{
            .context_id = context.context_id,
            .payload = payload,
        });
        self.payload_bytes += payload.len;
    }

    pub fn classifyOrBuffer(
        self: *PendingDatagramBuffer,
        registry: *const ContextRegistry,
        src: []const u8,
    ) Error!DatagramDisposition {
        const disposition = registry.classifyDatagramPayload(src);
        switch (disposition) {
            .unknown_context => |context| try self.bufferUnknown(context),
            else => {},
        }
        return disposition;
    }

    pub fn classifyCapsuleOrBuffer(
        self: *PendingDatagramBuffer,
        registry: *const ContextRegistry,
        capsule: capsule_mod.Capsule,
    ) Error!ReceiveDisposition {
        if (!capsule.isDatagram()) return .{ .ignored_capsule_type = capsule.capsule_type };
        const disposition = registry.classifyDatagramPayload(capsule.value);
        switch (disposition) {
            .unknown_context => |context| try self.bufferUnknown(context),
            else => {},
        }
        return receiveDispositionFromDatagram(disposition);
    }

    pub fn drainContext(
        self: *PendingDatagramBuffer,
        out_allocator: std.mem.Allocator,
        context_id: u64,
        out: *std.ArrayList(BufferedDatagram),
    ) std.mem.Allocator.Error!usize {
        var drained: usize = 0;
        var index: usize = 0;
        while (index < self.datagrams.items.len) {
            const datagram = self.datagrams.items[index];
            if (datagram.context_id != context_id) {
                index += 1;
                continue;
            }

            try out.append(out_allocator, datagram);
            _ = self.datagrams.swapRemove(index);
            self.payload_bytes -= datagram.payload.len;
            drained += 1;
        }
        return drained;
    }

    pub fn dropContext(self: *PendingDatagramBuffer, context_id: u64) usize {
        var dropped: usize = 0;
        var index: usize = 0;
        while (index < self.datagrams.items.len) {
            const datagram = self.datagrams.items[index];
            if (datagram.context_id != context_id) {
                index += 1;
                continue;
            }

            datagram.deinit(self.allocator);
            _ = self.datagrams.swapRemove(index);
            self.payload_bytes -= datagram.payload.len;
            dropped += 1;
        }
        return dropped;
    }

    fn reserve(self: *const PendingDatagramBuffer, payload_len: usize) Error!void {
        if (self.datagrams.items.len >= self.config.max_datagrams) return Error.ContextBufferFull;
        if (payload_len > self.config.max_payload_bytes or
            self.payload_bytes > self.config.max_payload_bytes - payload_len)
        {
            return Error.ContextBufferFull;
        }
    }
};

pub const ContextRegistry = struct {
    entries: [max_registered_contexts]RegisteredContext = [_]RegisteredContext{
        .{ .context_id = udp_context_id, .kind = .connect_udp },
    } ** max_registered_contexts,
    count: usize = 1,

    pub fn init() ContextRegistry {
        return .{};
    }

    pub fn kindOf(self: *const ContextRegistry, context_id: u64) ?ContextKind {
        if (self.indexOf(context_id)) |index| return self.entries[index].kind;
        return null;
    }

    pub fn isKnown(self: *const ContextRegistry, context_id: u64) bool {
        return self.kindOf(context_id) != null;
    }

    pub fn register(self: *ContextRegistry, context_id: u64, kind: ContextKind) Error!void {
        if (context_id == udp_context_id or self.indexOf(context_id) != null) {
            return Error.ContextAlreadyRegistered;
        }
        if (kind == .connect_udp) return Error.InvalidContextRegistration;
        if (self.count >= max_registered_contexts) return Error.ContextLimitExceeded;
        self.entries[self.count] = .{
            .context_id = context_id,
            .kind = kind,
        };
        self.count += 1;
    }

    pub fn registerExtension(self: *ContextRegistry, context_id: u64) Error!void {
        try self.register(context_id, .extension);
    }

    pub fn registerAllocatedExtension(
        self: *ContextRegistry,
        allocator_role: ContextIdAllocator,
        context_id: u64,
    ) Error!void {
        try validateAllocatedContextId(allocator_role, context_id);
        try self.registerExtension(context_id);
    }

    pub fn unregister(self: *ContextRegistry, context_id: u64) Error!void {
        if (context_id == udp_context_id) return Error.CannotUnregisterDefaultContext;
        const index = self.indexOf(context_id) orelse return Error.UnknownContext;
        self.count -= 1;
        if (index != self.count) {
            self.entries[index] = self.entries[self.count];
        }
    }

    pub fn decodeContextPayload(self: *const ContextRegistry, src: []const u8) Error!ContextPayload {
        const context = try datagram_mod.decodeContextPayload(src);
        const kind = self.kindOf(context.context_id) orelse return Error.UnknownContext;
        if (kind == .connect_udp) try validateUdpPayload(context.payload);
        return .{
            .context_id = context.context_id,
            .kind = kind,
            .payload = context.payload,
        };
    }

    pub fn decodeUdpPayload(self: *const ContextRegistry, src: []const u8) Error![]const u8 {
        const context = try self.decodeContextPayload(src);
        if (context.kind != .connect_udp) return Error.UnexpectedContext;
        return context.payload;
    }

    pub fn classifyDatagramPayload(self: *const ContextRegistry, src: []const u8) DatagramDisposition {
        const context = datagram_mod.decodeContextPayload(src) catch |err| {
            return .{ .abort_stream = streamAbortForError(err) };
        };
        const kind = self.kindOf(context.context_id) orelse {
            return .{ .unknown_context = context };
        };
        switch (kind) {
            .connect_udp => {
                validateUdpPayload(context.payload) catch |err| {
                    return .{ .abort_stream = streamAbortForError(err) };
                };
                return .{ .udp_payload = context.payload };
            },
            .extension => return .{ .extension_payload = .{
                .context_id = context.context_id,
                .kind = .extension,
                .payload = context.payload,
            } },
        }
    }

    fn indexOf(self: *const ContextRegistry, context_id: u64) ?usize {
        for (self.entries[0..self.count], 0..) |entry, index| {
            if (entry.context_id == context_id) return index;
        }
        return null;
    }
};

pub fn contextIdAllocator(context_id: u64) Error!ContextIdAllocator {
    if (context_id == udp_context_id) return Error.InvalidContextRegistration;
    return if (context_id & 1 == 0) .client else .proxy;
}

pub fn validateAllocatedContextId(allocator_role: ContextIdAllocator, context_id: u64) Error!void {
    const owner = try contextIdAllocator(context_id);
    if (owner != allocator_role) return Error.InvalidContextRegistration;
}

fn receiveDispositionFromDatagram(disposition: DatagramDisposition) ReceiveDisposition {
    return switch (disposition) {
        .udp_payload => |payload| .{ .udp_payload = payload },
        .extension_payload => |context| .{ .extension_payload = context },
        .unknown_context => |context| .{ .unknown_context = context },
        .abort_stream => |abort| .{ .abort_stream = abort },
    };
}

pub fn streamAbortForError(err: anyerror) StreamAbort {
    return .{
        .error_code = connect_udp_abort_code,
        .reason = abortReasonForError(err),
        .cause = err,
    };
}

pub fn abortReasonForError(err: anyerror) AbortReason {
    return switch (err) {
        error.UdpPayloadTooLarge => .udp_payload_too_large,
        error.UnexpectedContext => .unexpected_context,
        error.InsufficientBytes,
        error.InvalidLength,
        error.ValueTooLarge,
        => .malformed_context,
        else => .local_failure,
    };
}

pub fn isProtocolToken(value: []const u8) bool {
    return std.mem.eql(u8, value, connect_udp_protocol);
}

pub fn requestProtocol(fields: []const qpack.FieldLine) ?[]const u8 {
    return fieldValue(fields, ":protocol");
}

pub fn isConnectUdpRequest(fields: []const qpack.FieldLine) bool {
    const method = fieldValue(fields, ":method") orelse return false;
    const token = requestProtocol(fields) orelse return false;
    return std.mem.eql(u8, method, "CONNECT") and isProtocolToken(token);
}

pub fn isAcceptedStatus(status: []const u8) bool {
    if (status.len != 3 or status[0] != '2') return false;
    return std.ascii.isDigit(status[1]) and std.ascii.isDigit(status[2]);
}

pub fn responseAccepted(fields: []const qpack.FieldLine) bool {
    const status = fieldValue(fields, ":status") orelse return false;
    return isAcceptedStatus(status);
}

pub fn capsuleProtocolEnabled(fields: []const qpack.FieldLine) bool {
    const value = fieldValue(fields, capsule_protocol_header) orelse return false;
    return std.mem.eql(u8, value, capsule_protocol_value);
}

pub fn allocCapsuleProtocolHeaders(
    allocator: std.mem.Allocator,
    headers: []const qpack.FieldLine,
    enabled: bool,
) std.mem.Allocator.Error![]qpack.FieldLine {
    const add_header = enabled and !hasField(headers, capsule_protocol_header);
    const out = try allocator.alloc(qpack.FieldLine, headers.len + if (add_header) @as(usize, 1) else 0);
    @memcpy(out[0..headers.len], headers);
    if (add_header) {
        out[headers.len] = .{
            .name = capsule_protocol_header,
            .value = capsule_protocol_value,
        };
    }
    return out;
}

pub fn allocConnectUdpPath(allocator: std.mem.Allocator, options: ConnectUdpOptions) Error![]u8 {
    const target: ConnectUdpTarget = .{
        .host = options.target_host,
        .port = options.target_port,
    };
    const len = try connectUdpPathEncodedLen(options.path_prefix, target);
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    const n = try encodeConnectUdpPath(out, options.path_prefix, target);
    std.debug.assert(n == out.len);
    return out;
}

pub fn connectUdpPathEncodedLen(prefix: []const u8, target: ConnectUdpTarget) Error!usize {
    try validatePathPrefix(prefix);
    try validateTarget(target);
    const separator_len: usize = if (std.mem.endsWith(u8, prefix, "/")) 0 else 1;
    return prefix.len +
        separator_len +
        percentEncodedLen(target.host) +
        1 +
        std.fmt.count("{d}", .{target.port}) +
        1;
}

pub fn encodeConnectUdpPath(
    dst: []u8,
    prefix: []const u8,
    target: ConnectUdpTarget,
) Error!usize {
    const needed = try connectUdpPathEncodedLen(prefix, target);
    if (dst.len < needed) return Error.BufferTooSmall;

    var pos: usize = 0;
    @memcpy(dst[pos .. pos + prefix.len], prefix);
    pos += prefix.len;
    if (!std.mem.endsWith(u8, prefix, "/")) {
        dst[pos] = '/';
        pos += 1;
    }
    pos += percentEncodeSegment(dst[pos..], target.host);
    dst[pos] = '/';
    pos += 1;
    const port = std.fmt.bufPrint(dst[pos..], "{d}", .{target.port}) catch return Error.BufferTooSmall;
    pos += port.len;
    dst[pos] = '/';
    pos += 1;
    return pos;
}

pub fn parseConnectUdpTarget(
    allocator: std.mem.Allocator,
    path: []const u8,
    prefix: []const u8,
) Error!OwnedConnectUdpTarget {
    try validatePathPrefix(prefix);

    if (!std.mem.startsWith(u8, path, prefix)) return Error.InvalidConnectUdpPath;
    var rest = path[prefix.len..];
    if (!std.mem.endsWith(u8, prefix, "/")) {
        if (rest.len == 0 or rest[0] != '/') return Error.InvalidConnectUdpPath;
        rest = rest[1..];
    }
    if (rest.len == 0) return Error.InvalidConnectUdpPath;

    const host_end = std.mem.indexOfScalar(u8, rest, '/') orelse return Error.InvalidConnectUdpPath;
    const encoded_host = rest[0..host_end];
    rest = rest[host_end + 1 ..];
    if (encoded_host.len == 0 or rest.len == 0) return Error.InvalidConnectUdpPath;

    const port_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const port_text = rest[0..port_end];
    if (port_text.len == 0) return Error.InvalidConnectUdpPath;
    if (port_end < rest.len and rest[port_end + 1 ..].len != 0) return Error.InvalidConnectUdpPath;

    const port = std.fmt.parseUnsigned(u16, port_text, 10) catch return Error.InvalidConnectUdpPath;
    if (port == 0) return Error.InvalidConnectUdpTarget;

    const host = try percentDecodeSegment(allocator, encoded_host);
    errdefer allocator.free(host);
    if (host.len == 0) return Error.InvalidConnectUdpTarget;
    return .{
        .host = host,
        .port = port,
    };
}

pub fn udpPayloadEncodedLen(payload_len: usize) usize {
    return datagram_mod.contextPayloadEncodedLen(udp_context_id, payload_len);
}

pub fn udpPayloadEncodedLenChecked(payload_len: usize) Error!usize {
    try validateUdpPayloadLen(payload_len);
    return udpPayloadEncodedLen(payload_len);
}

pub fn encodeUdpPayload(dst: []u8, payload: []const u8) Error!usize {
    try validateUdpPayload(payload);
    return datagram_mod.encodeContextPayload(dst, udp_context_id, payload);
}

pub fn decodeUdpPayload(src: []const u8) Error![]const u8 {
    const context = try datagram_mod.decodeContextPayload(src);
    if (context.context_id != udp_context_id) return Error.UnexpectedContext;
    try validateUdpPayload(context.payload);
    return context.payload;
}

pub fn validateUdpPayload(payload: []const u8) Error!void {
    try validateUdpPayloadLen(payload.len);
}

pub fn validateUdpPayloadLen(payload_len: usize) Error!void {
    if (payload_len > max_udp_payload_len) return Error.UdpPayloadTooLarge;
}

fn validatePathPrefix(prefix: []const u8) Error!void {
    if (prefix.len == 0 or prefix[0] != '/') return Error.InvalidConnectUdpPath;
}

fn validateTarget(target: ConnectUdpTarget) Error!void {
    if (target.host.len == 0 or target.port == 0) return Error.InvalidConnectUdpTarget;
}

fn percentEncodedLen(input: []const u8) usize {
    var len: usize = 0;
    for (input) |byte| {
        len += if (isUnreserved(byte)) @as(usize, 1) else 3;
    }
    return len;
}

fn percentEncodeSegment(dst: []u8, input: []const u8) usize {
    const hex = "0123456789ABCDEF";
    var pos: usize = 0;
    for (input) |byte| {
        if (isUnreserved(byte)) {
            dst[pos] = byte;
            pos += 1;
        } else {
            dst[pos] = '%';
            dst[pos + 1] = hex[byte >> 4];
            dst[pos + 2] = hex[byte & 0x0f];
            pos += 3;
        }
    }
    return pos;
}

fn percentDecodeSegment(allocator: std.mem.Allocator, input: []const u8) Error![]u8 {
    var out = try allocator.alloc(u8, input.len);
    errdefer allocator.free(out);
    var read: usize = 0;
    var write: usize = 0;
    while (read < input.len) {
        if (input[read] != '%') {
            out[write] = input[read];
            read += 1;
            write += 1;
            continue;
        }
        if (input.len - read < 3) return Error.InvalidConnectUdpPath;
        const high = hexValue(input[read + 1]) orelse return Error.InvalidConnectUdpPath;
        const low = hexValue(input[read + 2]) orelse return Error.InvalidConnectUdpPath;
        out[write] = (high << 4) | low;
        read += 3;
        write += 1;
    }
    return try allocator.realloc(out, write);
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn hasField(fields: []const qpack.FieldLine, name: []const u8) bool {
    return fieldValue(fields, name) != null;
}

fn fieldValue(fields: []const qpack.FieldLine, name: []const u8) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

test "CONNECT-UDP path helpers percent-encode and parse targets" {
    const allocator = std.testing.allocator;
    const options: ConnectUdpOptions = .{
        .authority = "proxy.example",
        .target_host = "2001:db8::1",
        .target_port = 443,
    };
    const path = try allocConnectUdpPath(allocator, options);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/", path);

    const target = try parseConnectUdpTarget(allocator, path, default_connect_udp_path_prefix);
    defer target.deinit(allocator);
    try std.testing.expectEqualStrings("2001:db8::1", target.host);
    try std.testing.expectEqual(@as(u16, 443), target.port);

    try std.testing.expectError(
        Error.InvalidConnectUdpPath,
        parseConnectUdpTarget(allocator, "/.well-known/masque/udpx/example.com/443/", default_connect_udp_path_prefix),
    );
}

test "CONNECT-UDP request and capsule protocol helpers classify headers" {
    const allocator = std.testing.allocator;
    const headers = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "proxy.example" },
        .{ .name = ":path", .value = "/.well-known/masque/udp/example.com/443/" },
        .{ .name = ":protocol", .value = connect_udp_protocol },
    };
    try std.testing.expect(isConnectUdpRequest(&headers));
    try std.testing.expect(!capsuleProtocolEnabled(&headers));

    const with_capsules = try allocCapsuleProtocolHeaders(allocator, &headers, true);
    defer allocator.free(with_capsules);
    try std.testing.expect(capsuleProtocolEnabled(with_capsules));
}

test "CONNECT-UDP UDP payload helpers use context zero" {
    var buf: [64]u8 = undefined;
    const n = try encodeUdpPayload(&buf, "packet");
    try std.testing.expectEqualStrings("packet", try decodeUdpPayload(buf[0..n]));

    const bad_n = try datagram_mod.encodeContextPayload(&buf, 7, "packet");
    try std.testing.expectError(Error.UnexpectedContext, decodeUdpPayload(buf[0..bad_n]));
}

test "CONNECT-UDP context registry classifies known contexts" {
    var buf: [64]u8 = undefined;
    var registry = ContextRegistry.init();

    try std.testing.expect(registry.isKnown(udp_context_id));
    try std.testing.expectEqual(ContextKind.connect_udp, registry.kindOf(udp_context_id).?);
    try std.testing.expectError(Error.ContextAlreadyRegistered, registry.registerExtension(udp_context_id));
    try std.testing.expectError(Error.CannotUnregisterDefaultContext, registry.unregister(udp_context_id));
    try std.testing.expectError(Error.InvalidContextRegistration, registry.register(7, .connect_udp));

    const extension_n = try datagram_mod.encodeContextPayload(&buf, 7, "extension");
    try std.testing.expectError(Error.UnknownContext, registry.decodeContextPayload(buf[0..extension_n]));
    try registry.registerExtension(7);
    try std.testing.expect(registry.isKnown(7));

    const extension = try registry.decodeContextPayload(buf[0..extension_n]);
    try std.testing.expectEqual(@as(u64, 7), extension.context_id);
    try std.testing.expectEqual(ContextKind.extension, extension.kind);
    try std.testing.expectEqualStrings("extension", extension.payload);
    try std.testing.expectEqual(@as(u64, 7), extension.raw().context_id);
    try std.testing.expectError(Error.UnexpectedContext, registry.decodeUdpPayload(buf[0..extension_n]));
    try std.testing.expectError(Error.ContextAlreadyRegistered, registry.registerExtension(7));

    try registry.unregister(7);
    try std.testing.expect(!registry.isKnown(7));
    try std.testing.expectError(Error.UnknownContext, registry.unregister(7));
}

test "CONNECT-UDP context IDs enforce endpoint allocation parity" {
    try std.testing.expectEqual(ContextIdAllocator.client, try contextIdAllocator(2));
    try std.testing.expectEqual(ContextIdAllocator.proxy, try contextIdAllocator(3));
    try std.testing.expectError(Error.InvalidContextRegistration, contextIdAllocator(udp_context_id));
    try validateAllocatedContextId(.client, 2);
    try validateAllocatedContextId(.proxy, 3);
    try std.testing.expectError(Error.InvalidContextRegistration, validateAllocatedContextId(.client, 3));
    try std.testing.expectError(Error.InvalidContextRegistration, validateAllocatedContextId(.proxy, 2));

    var registry = ContextRegistry.init();
    try registry.registerAllocatedExtension(.client, 8);
    try std.testing.expect(registry.isKnown(8));
    try std.testing.expectError(Error.InvalidContextRegistration, registry.registerAllocatedExtension(.client, 9));
}

test "CONNECT-UDP pending datagram buffer drains after context registration" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    var registry = ContextRegistry.init();
    var pending = PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 4,
        .max_payload_bytes = 64,
    });
    defer pending.deinit();

    const first_n = try datagram_mod.encodeContextPayload(&buf, 8, "first");
    switch (try pending.classifyOrBuffer(&registry, buf[0..first_n])) {
        .unknown_context => |context| {
            try std.testing.expectEqual(@as(u64, 8), context.context_id);
            try std.testing.expectEqualStrings("first", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }
    const second_n = try datagram_mod.encodeContextPayload(&buf, 8, "second");
    _ = try pending.classifyOrBuffer(&registry, buf[0..second_n]);
    try std.testing.expectEqual(@as(usize, 2), pending.len());
    try std.testing.expectEqual(@as(usize, "first".len + "second".len), pending.bufferedPayloadBytes());

    try registry.registerAllocatedExtension(.client, 8);
    var drained: std.ArrayList(BufferedDatagram) = .empty;
    defer {
        freeBufferedDatagrams(allocator, drained.items);
        drained.deinit(allocator);
    }
    try std.testing.expectEqual(@as(usize, 2), try pending.drainContext(allocator, 8, &drained));
    try std.testing.expectEqual(@as(usize, 0), pending.len());
    try std.testing.expectEqual(@as(usize, 0), pending.bufferedPayloadBytes());

    const first = drained.items[0].context(.extension);
    const second = drained.items[1].context(.extension);
    try std.testing.expectEqual(@as(u64, 8), first.context_id);
    try std.testing.expectEqual(ContextKind.extension, first.kind);
    try std.testing.expectEqualStrings("first", first.payload);
    try std.testing.expectEqualStrings("second", second.payload);
    try std.testing.expectEqual(@as(u64, 8), drained.items[0].raw().context_id);

    const known_n = try datagram_mod.encodeContextPayload(&buf, 8, "known");
    switch (try pending.classifyOrBuffer(&registry, buf[0..known_n])) {
        .extension_payload => |context| try std.testing.expectEqualStrings("known", context.payload),
        else => return error.UnexpectedDisposition,
    }
    try std.testing.expectEqual(@as(usize, 0), pending.len());
}

test "CONNECT-UDP pending datagram buffer enforces limits and drops contexts" {
    const allocator = std.testing.allocator;
    var buf: [128]u8 = undefined;
    var registry = ContextRegistry.init();
    var pending = PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 1,
        .max_payload_bytes = 5,
    });
    defer pending.deinit();

    try std.testing.expectError(
        Error.UnexpectedContext,
        pending.bufferUnknown(.{ .context_id = udp_context_id, .payload = "udp" }),
    );

    const first_n = try datagram_mod.encodeContextPayload(&buf, 6, "abc");
    _ = try pending.classifyOrBuffer(&registry, buf[0..first_n]);
    try std.testing.expectEqual(@as(usize, 1), pending.len());

    const second_n = try datagram_mod.encodeContextPayload(&buf, 6, "de");
    try std.testing.expectError(Error.ContextBufferFull, pending.classifyOrBuffer(&registry, buf[0..second_n]));
    try std.testing.expectEqual(@as(usize, 1), pending.dropContext(6));
    try std.testing.expectEqual(@as(usize, 0), pending.len());

    const large_n = try datagram_mod.encodeContextPayload(&buf, 6, "abcdef");
    try std.testing.expectError(Error.ContextBufferFull, pending.classifyOrBuffer(&registry, buf[0..large_n]));
}

test "CONNECT-UDP pending datagram buffer classifies DATAGRAM capsules under pressure" {
    const allocator = std.testing.allocator;
    var context_buf: [64]u8 = undefined;
    var capsule_buf: [96]u8 = undefined;
    var registry = ContextRegistry.init();
    var pending = PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = 2,
        .max_payload_bytes = 8,
    });
    defer pending.deinit();

    const first_context_n = try datagram_mod.encodeContextPayload(&context_buf, 8, "abcd");
    const first_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..first_context_n]);
    const first_capsule = (try capsule_mod.decode(capsule_buf[0..first_capsule_n])).capsule;
    switch (try pending.classifyCapsuleOrBuffer(&registry, first_capsule)) {
        .unknown_context => |context| {
            try std.testing.expectEqual(@as(u64, 8), context.context_id);
            try std.testing.expectEqualStrings("abcd", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }
    try std.testing.expectEqual(@as(usize, 1), pending.len());
    try std.testing.expectEqual(@as(usize, 4), pending.bufferedPayloadBytes());

    const second_context_n = try datagram_mod.encodeContextPayload(&context_buf, 10, "efgh");
    const second_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..second_context_n]);
    const second_capsule = (try capsule_mod.decode(capsule_buf[0..second_capsule_n])).capsule;
    _ = try pending.classifyCapsuleOrBuffer(&registry, second_capsule);
    try std.testing.expectEqual(@as(usize, 2), pending.len());
    try std.testing.expectEqual(@as(usize, 8), pending.bufferedPayloadBytes());

    const ignored = try pending.classifyCapsuleOrBuffer(&registry, .{
        .capsule_type = 0x29 * 3 + 0x17,
        .value = "ignore",
    });
    try std.testing.expect(ignored.canSilentlyDrop());
    try std.testing.expectEqual(@as(usize, 2), pending.len());
    try std.testing.expectEqual(@as(usize, 8), pending.bufferedPayloadBytes());

    const malformed = try pending.classifyCapsuleOrBuffer(&registry, .{
        .capsule_type = capsule_mod.Type.datagram,
        .value = "",
    });
    switch (malformed) {
        .abort_stream => |abort| try std.testing.expectEqual(AbortReason.malformed_context, abort.reason),
        else => return error.UnexpectedDisposition,
    }
    try std.testing.expectEqual(@as(usize, 2), pending.len());
    try std.testing.expectEqual(@as(usize, 8), pending.bufferedPayloadBytes());

    const third_context_n = try datagram_mod.encodeContextPayload(&context_buf, 12, "");
    const third_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..third_context_n]);
    const third_capsule = (try capsule_mod.decode(capsule_buf[0..third_capsule_n])).capsule;
    try std.testing.expectError(Error.ContextBufferFull, pending.classifyCapsuleOrBuffer(&registry, third_capsule));
    try std.testing.expectEqual(@as(usize, 2), pending.len());
    try std.testing.expectEqual(@as(usize, 8), pending.bufferedPayloadBytes());

    try registry.registerAllocatedExtension(.client, 8);
    var drained: std.ArrayList(BufferedDatagram) = .empty;
    defer {
        freeBufferedDatagrams(allocator, drained.items);
        drained.deinit(allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), try pending.drainContext(allocator, 8, &drained));
    try std.testing.expectEqual(@as(usize, 1), pending.len());
    try std.testing.expectEqual(@as(usize, 4), pending.bufferedPayloadBytes());
    try std.testing.expectEqualStrings("abcd", drained.items[0].payload);

    const known_context_n = try datagram_mod.encodeContextPayload(&context_buf, 8, "known");
    const known_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..known_context_n]);
    const known_capsule = (try capsule_mod.decode(capsule_buf[0..known_capsule_n])).capsule;
    switch (try pending.classifyCapsuleOrBuffer(&registry, known_capsule)) {
        .extension_payload => |context| {
            try std.testing.expectEqual(@as(u64, 8), context.context_id);
            try std.testing.expectEqualStrings("known", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }
    try std.testing.expectEqual(@as(usize, 1), pending.len());
    try std.testing.expectEqual(@as(usize, 4), pending.bufferedPayloadBytes());

    try std.testing.expectEqual(@as(usize, 1), pending.dropContext(10));
    try std.testing.expectEqual(@as(usize, 0), pending.len());
    try std.testing.expectEqual(@as(usize, 0), pending.bufferedPayloadBytes());
}

test "CONNECT-UDP pending datagram buffer survives sustained capsule fill and drain cycles" {
    const allocator = std.testing.allocator;
    const payloads = [_][]const u8{ "aa", "bbb", "c", "dddd" };
    var context_buf: [64]u8 = undefined;
    var capsule_buf: [96]u8 = undefined;
    var registry = ContextRegistry.init();
    var pending = PendingDatagramBuffer.initWithConfig(allocator, .{
        .max_datagrams = payloads.len,
        .max_payload_bytes = 10,
    });
    defer pending.deinit();

    var cycle: usize = 0;
    while (cycle < 32) : (cycle += 1) {
        const context_id: u64 = 8 + @as(u64, @intCast(cycle)) * 2;
        var total_payload_bytes: usize = 0;
        for (payloads) |payload| {
            total_payload_bytes += payload.len;
            const context_n = try datagram_mod.encodeContextPayload(&context_buf, context_id, payload);
            const capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..context_n]);
            const capsule = (try capsule_mod.decode(capsule_buf[0..capsule_n])).capsule;
            switch (try pending.classifyCapsuleOrBuffer(&registry, capsule)) {
                .unknown_context => |context| {
                    try std.testing.expectEqual(context_id, context.context_id);
                    try std.testing.expectEqualStrings(payload, context.payload);
                },
                else => return error.UnexpectedDisposition,
            }
        }

        try std.testing.expectEqual(payloads.len, pending.len());
        try std.testing.expectEqual(total_payload_bytes, pending.bufferedPayloadBytes());

        const overflow_context_n = try datagram_mod.encodeContextPayload(&context_buf, context_id, "z");
        const overflow_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..overflow_context_n]);
        const overflow_capsule = (try capsule_mod.decode(capsule_buf[0..overflow_capsule_n])).capsule;
        try std.testing.expectError(
            Error.ContextBufferFull,
            pending.classifyCapsuleOrBuffer(&registry, overflow_capsule),
        );
        try std.testing.expectEqual(payloads.len, pending.len());
        try std.testing.expectEqual(total_payload_bytes, pending.bufferedPayloadBytes());

        try registry.registerAllocatedExtension(.client, context_id);
        var drained: std.ArrayList(BufferedDatagram) = .empty;
        try std.testing.expectEqual(payloads.len, try pending.drainContext(allocator, context_id, &drained));
        try std.testing.expectEqual(@as(usize, 0), pending.len());
        try std.testing.expectEqual(@as(usize, 0), pending.bufferedPayloadBytes());
        for (payloads) |payload| {
            var found = false;
            for (drained.items) |datagram| {
                try std.testing.expectEqual(context_id, datagram.context_id);
                if (std.mem.eql(u8, payload, datagram.payload)) found = true;
            }
            try std.testing.expect(found);
        }
        freeBufferedDatagrams(allocator, drained.items);
        drained.deinit(allocator);
        try registry.unregister(context_id);
    }
}

test "CONNECT-UDP datagram disposition separates unknown context from stream aborts" {
    const allocator = std.testing.allocator;
    var buf: [64]u8 = undefined;
    var registry = ContextRegistry.init();

    const udp_n = try encodeUdpPayload(&buf, "packet");
    switch (registry.classifyDatagramPayload(buf[0..udp_n])) {
        .udp_payload => |payload| try std.testing.expectEqualStrings("packet", payload),
        else => return error.UnexpectedDisposition,
    }

    const unknown_n = try datagram_mod.encodeContextPayload(&buf, 7, "future");
    switch (registry.classifyDatagramPayload(buf[0..unknown_n])) {
        .unknown_context => |context| {
            try std.testing.expectEqual(@as(u64, 7), context.context_id);
            try std.testing.expectEqualStrings("future", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }

    try registry.registerExtension(7);
    switch (registry.classifyDatagramPayload(buf[0..unknown_n])) {
        .extension_payload => |context| {
            try std.testing.expectEqual(@as(u64, 7), context.context_id);
            try std.testing.expectEqual(ContextKind.extension, context.kind);
            try std.testing.expectEqualStrings("future", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }

    switch (registry.classifyDatagramPayload("")) {
        .abort_stream => |abort| {
            try std.testing.expectEqual(connect_udp_abort_code, abort.error_code);
            try std.testing.expectEqual(AbortReason.malformed_context, abort.reason);
        },
        else => return error.UnexpectedDisposition,
    }

    const too_large = try allocator.alloc(u8, max_udp_payload_len + 1);
    defer allocator.free(too_large);
    const encoded = try allocator.alloc(u8, udpPayloadEncodedLen(too_large.len));
    defer allocator.free(encoded);
    const encoded_n = try datagram_mod.encodeContextPayload(encoded, udp_context_id, too_large);
    switch (registry.classifyDatagramPayload(encoded[0..encoded_n])) {
        .abort_stream => |abort| {
            try std.testing.expectEqual(connect_udp_abort_code, abort.error_code);
            try std.testing.expectEqual(AbortReason.udp_payload_too_large, abort.reason);
            try std.testing.expectEqual(error.UdpPayloadTooLarge, abort.cause.?);
        },
        else => return error.UnexpectedDisposition,
    }
}

test "CONNECT-UDP receiver classifies datagram capsules" {
    var context_buf: [64]u8 = undefined;
    var capsule_buf: [128]u8 = undefined;
    var receiver = ConnectUdpReceiver.init();

    const payload_n = try encodeUdpPayload(&context_buf, "packet");
    const capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..payload_n]);
    const decoded = try capsule_mod.decode(capsule_buf[0..capsule_n]);
    switch (receiver.classifyCapsule(decoded.capsule)) {
        .udp_payload => |payload| try std.testing.expectEqualStrings("packet", payload),
        else => return error.UnexpectedDisposition,
    }

    const unknown_context_n = try datagram_mod.encodeContextPayload(&context_buf, 8, "optimistic");
    const unknown_capsule_n = try capsule_mod.encodeDatagram(&capsule_buf, context_buf[0..unknown_context_n]);
    const unknown_decoded = try capsule_mod.decode(capsule_buf[0..unknown_capsule_n]);
    const unknown = receiver.classifyCapsule(unknown_decoded.capsule);
    try std.testing.expect(unknown.canSilentlyDrop());
    switch (unknown) {
        .unknown_context => |context| {
            try std.testing.expectEqual(@as(u64, 8), context.context_id);
            try std.testing.expectEqualStrings("optimistic", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }

    try receiver.registerExtension(8);
    switch (receiver.classifyCapsule(unknown_decoded.capsule)) {
        .extension_payload => |context| {
            try std.testing.expectEqual(@as(u64, 8), context.context_id);
            try std.testing.expectEqual(ContextKind.extension, context.kind);
            try std.testing.expectEqualStrings("optimistic", context.payload);
        },
        else => return error.UnexpectedDisposition,
    }

    const ignored = receiver.classifyCapsule(.{
        .capsule_type = 0x29 * 3 + 0x17,
        .value = "ignore",
    });
    try std.testing.expect(ignored.canSilentlyDrop());
    switch (ignored) {
        .ignored_capsule_type => |capsule_type| try std.testing.expectEqual(@as(u64, 0x92), capsule_type),
        else => return error.UnexpectedDisposition,
    }

    switch (receiver.classifyDatagramPayload("")) {
        .abort_stream => |abort| try std.testing.expectEqual(AbortReason.malformed_context, abort.reason),
        else => return error.UnexpectedDisposition,
    }
}

test "CONNECT-UDP context registry enforces fixed capacity" {
    var registry = ContextRegistry.init();

    var context_id: u64 = 1;
    while (context_id < max_registered_contexts) : (context_id += 1) {
        try registry.registerExtension(context_id);
    }
    try std.testing.expectEqual(max_registered_contexts, registry.count);
    try std.testing.expectError(Error.ContextLimitExceeded, registry.registerExtension(max_registered_contexts));
}

test "CONNECT-UDP UDP payload helpers enforce payload size" {
    const allocator = std.testing.allocator;
    const too_large = try allocator.alloc(u8, max_udp_payload_len + 1);
    defer allocator.free(too_large);

    var small_buf: [1]u8 = undefined;
    try std.testing.expectError(Error.UdpPayloadTooLarge, udpPayloadEncodedLenChecked(too_large.len));
    try std.testing.expectError(Error.UdpPayloadTooLarge, encodeUdpPayload(&small_buf, too_large));

    const encoded = try allocator.alloc(u8, udpPayloadEncodedLen(too_large.len));
    defer allocator.free(encoded);
    const n = try datagram_mod.encodeContextPayload(encoded, udp_context_id, too_large);
    try std.testing.expectError(Error.UdpPayloadTooLarge, decodeUdpPayload(encoded[0..n]));

    const registry = ContextRegistry.init();
    try std.testing.expectError(Error.UdpPayloadTooLarge, registry.decodeContextPayload(encoded[0..n]));
}
