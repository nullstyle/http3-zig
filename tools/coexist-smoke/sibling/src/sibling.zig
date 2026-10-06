//! The sibling's public surface: its own `quic` and `boringssl` imports.
pub const quic = @import("quic");
pub const boringssl = @import("boringssl");
