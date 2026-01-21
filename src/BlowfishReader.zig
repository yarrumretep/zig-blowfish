const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const Blowfish = @import("Blowfish.zig");

/// A decrypting reader that wraps another reader and decrypts Blowfish-encrypted data.
/// Implements the std.Io.Reader interface for chaining with other readers/writers.
pub const BlowfishReader = struct {
    /// The upstream encrypted reader
    source: *Io.Reader,
    /// Blowfish cipher state
    blowfish: Blowfish,
    /// Buffer for decrypted data (one block)
    decrypted_buffer: [8]u8 = .{0} ** 8,
    /// Slice of decrypted_buffer that hasn't been consumed yet
    current_decrypted_start: usize = 0,
    current_decrypted_end: usize = 0,
    /// Buffer for reading encrypted blocks
    encrypted_buffer: [8]u8 = undefined,
    encrypted_buffer_len: usize = 0,
    /// Error state
    err: ?Error = null,
    /// The std.Io.Reader interface - must be last for @fieldParentPtr
    interface: Io.Reader,

    pub const Error = error{ UnevenBytesInStream, ReadFailed };

    const vtable: Io.Reader.VTable = .{
        .stream = stream,
        .discard = discard,
    };

    pub fn init(key: []const u8, source: *Io.Reader, buffer: []u8) BlowfishReader {
        return .{
            .source = source,
            .blowfish = Blowfish.init(key),
            .interface = .{
                .vtable = &vtable,
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Stream decrypted data to a writer
    fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const self: *BlowfishReader = @alignCast(@fieldParentPtr("interface", r));

        if (self.err) |_| return error.ReadFailed;

        var total_written: usize = 0;
        var remaining = limit;

        // First, write any buffered decrypted data
        while (self.current_decrypted_start < self.current_decrypted_end and remaining.nonzero()) {
            const available = self.decrypted_buffer[self.current_decrypted_start..self.current_decrypted_end];
            const to_write = remaining.minInt(available.len);
            const n = w.write(available[0..to_write]) catch return error.WriteFailed;
            self.current_decrypted_start += n;
            total_written += n;
            remaining = remaining.subtract(n) orelse break;
        }

        // Read and decrypt more blocks
        while (remaining.nonzero()) {
            // Try to read a full 8-byte encrypted block
            while (self.encrypted_buffer_len < 8) {
                const read_result = self.source.readSliceShort(self.encrypted_buffer[self.encrypted_buffer_len..8]);
                const ct = read_result catch {
                    self.err = error.ReadFailed;
                    return if (total_written > 0) total_written else error.ReadFailed;
                };
                if (ct == 0) {
                    // EOF
                    if (self.encrypted_buffer_len > 0) {
                        self.err = error.UnevenBytesInStream;
                        return if (total_written > 0) total_written else error.ReadFailed;
                    }
                    return if (total_written > 0) total_written else error.EndOfStream;
                }
                self.encrypted_buffer_len += ct;
            }

            // Decrypt the block
            self.blowfish.decrypt(&self.encrypted_buffer, &self.decrypted_buffer);
            self.encrypted_buffer_len = 0;
            self.current_decrypted_start = 0;
            self.current_decrypted_end = 8;

            // Write decrypted data
            const to_write = remaining.minInt(8);
            const n = w.write(self.decrypted_buffer[0..to_write]) catch return error.WriteFailed;
            self.current_decrypted_start = n;
            total_written += n;
            remaining = remaining.subtract(n) orelse break;
        }

        return total_written;
    }

    /// Discard decrypted data without providing access
    fn discard(r: *Io.Reader, limit: Io.Limit) Io.Reader.Error!usize {
        const self: *BlowfishReader = @alignCast(@fieldParentPtr("interface", r));

        if (self.err) |_| return error.ReadFailed;

        var total_discarded: usize = 0;
        var remaining = limit;

        // First, discard any buffered decrypted data
        while (self.current_decrypted_start < self.current_decrypted_end and remaining.nonzero()) {
            const available = self.current_decrypted_end - self.current_decrypted_start;
            const to_discard = remaining.minInt(available);
            self.current_decrypted_start += to_discard;
            total_discarded += to_discard;
            remaining = remaining.subtract(to_discard) orelse break;
        }

        // Read and decrypt more blocks, discarding the output
        while (remaining.nonzero()) {
            // Try to read a full 8-byte encrypted block
            while (self.encrypted_buffer_len < 8) {
                const read_result = self.source.readSliceShort(self.encrypted_buffer[self.encrypted_buffer_len..8]);
                const ct = read_result catch {
                    self.err = error.ReadFailed;
                    return if (total_discarded > 0) total_discarded else error.ReadFailed;
                };
                if (ct == 0) {
                    // EOF
                    if (self.encrypted_buffer_len > 0) {
                        self.err = error.UnevenBytesInStream;
                        return if (total_discarded > 0) total_discarded else error.ReadFailed;
                    }
                    return if (total_discarded > 0) total_discarded else error.EndOfStream;
                }
                self.encrypted_buffer_len += ct;
            }

            // Decrypt the block
            self.blowfish.decrypt(&self.encrypted_buffer, &self.decrypted_buffer);
            self.encrypted_buffer_len = 0;

            // Discard decrypted data
            const to_discard = remaining.minInt(8);
            self.current_decrypted_start = to_discard;
            self.current_decrypted_end = 8;
            total_discarded += to_discard;
            remaining = remaining.subtract(to_discard) orelse break;
        }

        return total_discarded;
    }

    /// Convenience function to decrypt all data to a writer
    pub fn decryptAll(self: *BlowfishReader, writer: *Io.Writer) !void {
        _ = self.interface.streamRemaining(writer) catch |err| switch (err) {
            error.ReadFailed => {
                if (self.err) |e| return e;
                return error.ReadFailed;
            },
            error.WriteFailed => return error.WriteFailed,
        };
    }
};

pub fn blowfishReader(key: []const u8, source: *Io.Reader, buffer: []u8) BlowfishReader {
    return BlowfishReader.init(key, source, buffer);
}

test "memory reader" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var source: Io.Reader = .fixed(encrypted[0..8]);
    var buf: [64]u8 = undefined;
    var bf_reader = blowfishReader(key, &source, &buf);

    var decrypted: [8]u8 = undefined;
    bf_reader.interface.readSliceAll(&decrypted) catch |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.ReadFailed,
    };
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 }, decrypted);
}

test "memory reader short read" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var source: Io.Reader = .fixed(encrypted[0..]);
    var buf: [64]u8 = undefined;
    var bf_reader = blowfishReader(key, &source, &buf);

    var decrypted: [1]u8 = undefined;
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x01}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{0x02}, decrypted);
}

test "memory reader overlapping read" {
    const key = "TESTKEY";
    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var source: Io.Reader = .fixed(encrypted[0..]);
    var buf: [64]u8 = undefined;
    var bf_reader = blowfishReader(key, &source, &buf);

    var decrypted: [3]u8 = undefined;
    try std.testing.expectEqual(3, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x01, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x02, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x01 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqual(0x02, decrypted[0]);
    try std.testing.expectEqual(0, try bf_reader.interface.readSliceShort(decrypted[0..]));
}

test "memory reader big buffer" {
    const key = "TESTKEY";
    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var source: Io.Reader = .fixed(encrypted[0..]);
    var buf: [64]u8 = undefined;
    var bf_reader = blowfishReader(key, &source, &buf);

    var decrypted: [15]u8 = undefined;
    try std.testing.expectEqual(15, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }, decrypted);
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(1, try bf_reader.interface.readSliceShort(one[0..]));
    try std.testing.expectEqual(0x02, one[0]);
}

test "read padded" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0x6c, 0x44, 0xdc, 0xed, 0x6c, 0xa6, 0x34, 0x79 };
    var source: Io.Reader = .fixed(encrypted[0..]);
    var buf: [64]u8 = undefined;
    var bf_reader = blowfishReader(key, &source, &buf);

    var decrypted: [8]u8 = undefined;
    try std.testing.expectEqual(8, try bf_reader.interface.readSliceShort(decrypted[0..]));
    try std.testing.expectEqualDeep([_]u8{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, decrypted);
}
