//! null3 — HTTP/3 for Zig, layered above nullq and boringssl-zig.

const std = @import("std");
const boringssl = @import("boringssl");
const nullq = @import("nullq");

pub const protocol = @import("protocol.zig");
pub const settings = @import("settings.zig");
pub const frame = @import("frame.zig");
pub const qpack = @import("qpack/root.zig");
pub const headers = @import("headers.zig");
pub const stream = @import("stream.zig");
pub const priority = @import("priority.zig");
pub const message = @import("message.zig");
pub const errors = @import("errors.zig");
pub const session = @import("session.zig");
pub const connection = @import("connection.zig");
pub const client = @import("client.zig");
pub const server = @import("server.zig");

pub const Session = session.Session;
pub const ShutdownState = session.ShutdownState;
pub const Client = client.Client;
pub const Server = server.Server;
pub const RequestOptions = client.RequestOptions;
pub const RequestHeadOptions = client.RequestHeadOptions;
pub const RequestWriter = client.RequestWriter;
pub const ResponseState = client.ResponseState;
pub const ResponseReader = client.ResponseReader;
pub const ResponseTracker = client.ResponseTracker;
pub const ResponseOptions = server.ResponseOptions;
pub const ResponseHeadOptions = server.ResponseHeadOptions;
pub const ResponseWriter = server.ResponseWriter;
pub const RequestState = server.RequestState;
pub const RequestReader = server.RequestReader;
pub const RequestTracker = server.RequestTracker;
pub const Connection = connection.Connection;
pub const Settings = settings.Settings;
pub const Frame = frame.Frame;
pub const FieldLine = qpack.FieldLine;
pub const DynamicTable = qpack.DynamicTable;
pub const Priority = priority.Priority;
pub const MessageEncoder = message.Encoder;
pub const MessageDecoder = message.Decoder;
pub const ErrorScope = errors.Scope;
pub const ErrorSource = errors.Source;
pub const ErrorCategory = errors.Category;
pub const ApplicationError = errors.ApplicationError;
pub const ConnectionError = errors.ConnectionError;
pub const StreamError = errors.StreamError;

pub fn version() []const u8 {
    return "0.0.0";
}

test {
    _ = boringssl;
    _ = nullq;
    _ = protocol;
    _ = settings;
    _ = frame;
    _ = qpack;
    _ = headers;
    _ = stream;
    _ = priority;
    _ = message;
    _ = errors;
    _ = session;
    _ = connection;
    _ = client;
    _ = server;
}

test "package metadata" {
    try std.testing.expectEqualStrings("0.0.0", version());
    try std.testing.expectEqualStrings("h3", protocol.alpn_h3);
}
