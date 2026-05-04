//! HTTP/3 connection adapter over nullq.Connection.

const nullq = @import("nullq");
const protocol = @import("protocol.zig");
const settings_mod = @import("settings.zig");
const frame_mod = @import("frame.zig");

const varint = nullq.wire.varint;

pub const Error = nullq.conn.state.Error || frame_mod.Error || varint.Error || error{
    CriticalStreamAlreadyOpen,
    QpackStreamsAlreadyOpen,
    InvalidRole,
    WriteStalled,
};

pub const Config = struct {
    settings: settings_mod.Settings = .{},
    /// Literal-only QPACK does not need the encoder/decoder streams.
    /// Enable this once dynamic-table support is configured.
    open_qpack_streams: bool = false,
};

pub const Connection = struct {
    role: protocol.Role,
    quic: *nullq.Connection,
    local_settings: settings_mod.Settings,
    control_stream_id: ?u64 = null,
    qpack_encoder_stream_id: ?u64 = null,
    qpack_decoder_stream_id: ?u64 = null,

    pub fn init(role: protocol.Role, quic: *nullq.Connection, config: Config) Connection {
        return .{
            .role = role,
            .quic = quic,
            .local_settings = config.settings,
        };
    }

    pub fn openCriticalStreams(self: *Connection, config: Config) Error!void {
        try self.openControlStream();
        if (config.open_qpack_streams) try self.openQpackStreams();
    }

    pub fn openControlStream(self: *Connection) Error!u64 {
        if (self.control_stream_id != null) return Error.CriticalStreamAlreadyOpen;
        const id = self.nextLocalUniId(0);
        _ = try self.quic.openUni(id);
        try self.writeStreamType(id, protocol.StreamType.control);

        var settings_buf: [256]u8 = undefined;
        const settings_frame_len = try frame_mod.encode(&settings_buf, .{
            .settings = self.local_settings,
        });
        try self.writeAll(id, settings_buf[0..settings_frame_len]);

        self.control_stream_id = id;
        return id;
    }

    pub fn openQpackStreams(self: *Connection) Error!void {
        if (self.qpack_encoder_stream_id != null or self.qpack_decoder_stream_id != null) {
            return Error.QpackStreamsAlreadyOpen;
        }
        const enc_id = self.nextLocalUniId(0);
        _ = try self.quic.openUni(enc_id);
        try self.writeStreamType(enc_id, protocol.StreamType.qpack_encoder);

        const dec_id = self.nextLocalUniId(enc_id + 4);
        _ = try self.quic.openUni(dec_id);
        try self.writeStreamType(dec_id, protocol.StreamType.qpack_decoder);

        self.qpack_encoder_stream_id = enc_id;
        self.qpack_decoder_stream_id = dec_id;
    }

    pub fn openRequestStream(self: *Connection) Error!u64 {
        if (self.role != .client) return Error.InvalidRole;
        const id = self.nextLocalBidiId(0);
        _ = try self.quic.openBidi(id);
        return id;
    }

    pub fn sendHeaders(self: *Connection, stream_id: u64, field_section: []const u8) Error!void {
        var prefix: [16]u8 = undefined;
        var pos: usize = 0;
        pos += try varint.encode(prefix[pos..], protocol.FrameType.headers);
        pos += try varint.encode(prefix[pos..], field_section.len);
        try self.writeAll(stream_id, prefix[0..pos]);
        try self.writeAll(stream_id, field_section);
    }

    pub fn sendData(self: *Connection, stream_id: u64, data: []const u8) Error!void {
        var prefix: [16]u8 = undefined;
        var pos: usize = 0;
        pos += try varint.encode(prefix[pos..], protocol.FrameType.data);
        pos += try varint.encode(prefix[pos..], data.len);
        try self.writeAll(stream_id, prefix[0..pos]);
        try self.writeAll(stream_id, data);
    }

    fn writeStreamType(self: *Connection, stream_id: u64, stream_type: u64) Error!void {
        var buf: [8]u8 = undefined;
        const n = try varint.encode(&buf, stream_type);
        try self.writeAll(stream_id, buf[0..n]);
    }

    fn writeAll(self: *Connection, stream_id: u64, bytes: []const u8) Error!void {
        var rest = bytes;
        while (rest.len > 0) {
            const n = try self.quic.streamWrite(stream_id, rest);
            if (n == 0) return Error.WriteStalled;
            rest = rest[n..];
        }
    }

    fn nextLocalUniId(self: *const Connection, start: u64) u64 {
        const low_bits: u64 = switch (self.role) {
            .client => 0b10,
            .server => 0b11,
        };
        var id = (start & ~@as(u64, 0b11)) | low_bits;
        while (self.quic.stream(id) != null) id += 4;
        return id;
    }

    fn nextLocalBidiId(self: *const Connection, start: u64) u64 {
        const low_bits: u64 = switch (self.role) {
            .client => 0b00,
            .server => 0b01,
        };
        var id = (start & ~@as(u64, 0b11)) | low_bits;
        while (self.quic.stream(id) != null) id += 4;
        return id;
    }
};
