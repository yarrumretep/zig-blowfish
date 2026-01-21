const std = @import("std");
const Io = std.Io;
const Blowfish = @import("Blowfish.zig");

/// An encrypting writer that wraps another writer and encrypts data with Blowfish.
/// Implements the std.Io.Writer interface for chaining with other readers/writers.
pub const BlowfishWriter = struct {
    /// The downstream encrypted writer
    dest: *Io.Writer,
    /// Blowfish cipher state
    blowfish: Blowfish,
    /// Buffer for unencrypted data waiting to form a complete block
    unencrypted_buffer: [8]u8 = .{0} ** 8,
    unencrypted_len: usize = 0,
    /// The std.Io.Writer interface
    writer: Io.Writer,

    const vtable: Io.Writer.VTable = .{
        .drain = drain,
        .flush = flush,
    };

    pub fn init(key: []const u8, dest: *Io.Writer, buffer: []u8) BlowfishWriter {
        return .{
            .dest = dest,
            .blowfish = Blowfish.init(key),
            .writer = .{
                .vtable = &vtable,
                .buffer = buffer,
                .end = 0,
            },
        };
    }

    /// Drain buffered data to the destination, encrypting complete blocks
    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *BlowfishWriter = @alignCast(@fieldParentPtr("writer", w));

        // Calculate total bytes to process
        var total_bytes: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            total_bytes += slice.len;
        }
        total_bytes += data[data.len - 1].len * splat;

        // Also include any data already in w.buffer
        total_bytes += w.end;

        var consumed: usize = 0;
        var encrypted_buffer: [8]u8 = undefined;

        // Helper to get next byte from the combined sources
        const Sources = struct {
            w_buffer: []const u8,
            w_pos: usize,
            data: []const []const u8,
            data_idx: usize,
            data_pos: usize,
            splat: usize,
            splat_count: usize,

            fn next(s: *@This()) ?u8 {
                // First drain w.buffer
                if (s.w_pos < s.w_buffer.len) {
                    const b = s.w_buffer[s.w_pos];
                    s.w_pos += 1;
                    return b;
                }
                // Then drain data slices
                while (s.data_idx < s.data.len) {
                    const is_last = s.data_idx == s.data.len - 1;
                    const slice = s.data[s.data_idx];

                    if (s.data_pos < slice.len) {
                        const b = slice[s.data_pos];
                        s.data_pos += 1;
                        return b;
                    }

                    if (is_last and s.splat_count < s.splat) {
                        // Repeat the last slice
                        s.splat_count += 1;
                        if (s.splat_count < s.splat) {
                            s.data_pos = 0;
                            continue;
                        }
                    }

                    s.data_idx += 1;
                    s.data_pos = 0;
                }
                return null;
            }
        };

        var sources = Sources{
            .w_buffer = w.buffer[0..w.end],
            .w_pos = 0,
            .data = data,
            .data_idx = 0,
            .data_pos = 0,
            .splat = splat,
            .splat_count = 0,
        };

        // First, try to complete any partial block in self.unencrypted_buffer
        while (self.unencrypted_len < 8) {
            if (sources.next()) |b| {
                self.unencrypted_buffer[self.unencrypted_len] = b;
                self.unencrypted_len += 1;
                consumed += 1;
            } else break;
        }

        // If we have a complete block, encrypt and write it
        if (self.unencrypted_len == 8) {
            self.blowfish.encrypt(&self.unencrypted_buffer, &encrypted_buffer);
            self.dest.writeAll(&encrypted_buffer) catch return error.WriteFailed;
            self.unencrypted_len = 0;
        }

        // Process remaining complete blocks
        var block: [8]u8 = undefined;
        var block_pos: usize = 0;

        while (true) {
            if (sources.next()) |b| {
                block[block_pos] = b;
                block_pos += 1;
                consumed += 1;

                if (block_pos == 8) {
                    self.blowfish.encrypt(&block, &encrypted_buffer);
                    self.dest.writeAll(&encrypted_buffer) catch return error.WriteFailed;
                    block_pos = 0;
                }
            } else break;
        }

        // Save any remaining partial block
        if (block_pos > 0) {
            @memcpy(self.unencrypted_buffer[0..block_pos], block[0..block_pos]);
            self.unencrypted_len = block_pos;
        }

        // Clear the interface buffer since we consumed it
        w.end = 0;

        // Return bytes consumed from data (not including w.buffer)
        return consumed - sources.w_pos;
    }

    /// Flush any remaining data, padding with zeros if necessary
    fn flush(w: *Io.Writer) Io.Writer.Error!void {
        const self: *BlowfishWriter = @alignCast(@fieldParentPtr("writer", w));

        // First flush any data in the interface buffer
        if (w.end > 0) {
            _ = try drain(w, &.{""}, 1);
        }

        // Then pad and encrypt any partial block
        if (self.unencrypted_len > 0) {
            // Pad with zeros
            @memset(self.unencrypted_buffer[self.unencrypted_len..8], 0);
            var encrypted_buffer: [8]u8 = undefined;
            self.blowfish.encrypt(&self.unencrypted_buffer, &encrypted_buffer);
            self.dest.writeAll(&encrypted_buffer) catch return error.WriteFailed;
            self.unencrypted_len = 0;
        }

        // Flush the destination
        try self.dest.flush();
    }

    /// Convenience function to encrypt all data from a reader
    pub fn encryptAll(self: *BlowfishWriter, reader: *Io.Reader) !void {
        _ = reader.streamRemaining(&self.writer) catch |err| switch (err) {
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => return error.WriteFailed,
        };
        try self.writer.flush();
    }
};

pub fn blowfishWriter(key: []const u8, dest: *Io.Writer, buffer: []u8) BlowfishWriter {
    return BlowfishWriter.init(key, dest, buffer);
}

test "writer" {
    var output_buffer: [16]u8 = undefined;
    var dest: Io.Writer = .fixed(&output_buffer);
    var buf: [64]u8 = undefined;
    var bfwriter = blowfishWriter("TESTKEY", &dest, &buf);

    const unencrypted: [8]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    try bfwriter.writer.writeAll(&unencrypted);
    try bfwriter.writer.flush();

    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(encrypted, output_buffer[0..8].*);
}

test "weird buffer lengths" {
    var output_buffer: [16]u8 = undefined;
    var dest: Io.Writer = .fixed(&output_buffer);
    var buf: [64]u8 = undefined;
    var bfwriter = blowfishWriter("TESTKEY", &dest, &buf);

    const unencrypted: [8]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    try bfwriter.writer.writeAll(unencrypted[0..3]);
    try bfwriter.writer.writeAll(unencrypted[3..]);
    try bfwriter.writer.flush();

    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(encrypted, output_buffer[0..8].*);
}

test "more weird buffer lengths" {
    var output_buffer: [32]u8 = undefined;
    var dest: Io.Writer = .fixed(&output_buffer);
    var buf: [64]u8 = undefined;
    var bfwriter = blowfishWriter("TESTKEY", &dest, &buf);

    const unencrypted: [16]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    try bfwriter.writer.writeAll(unencrypted[0..3]);
    try bfwriter.writer.writeAll(unencrypted[3..10]);
    try bfwriter.writer.writeAll(unencrypted[10..]);
    try bfwriter.writer.flush();

    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(encrypted, output_buffer[0..16].*);
}

test "padding" {
    var output_buffer: [16]u8 = undefined;
    var dest: Io.Writer = .fixed(&output_buffer);
    var buf: [64]u8 = undefined;
    var bfwriter = blowfishWriter("TESTKEY", &dest, &buf);

    const unencrypted: [5]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00 };
    try bfwriter.writer.writeAll(&unencrypted);
    try bfwriter.writer.flush();

    const encrypted: [8]u8 = .{ 0x6c, 0x44, 0xdc, 0xed, 0x6c, 0xa6, 0x34, 0x79 };
    try std.testing.expectEqualDeep(encrypted, output_buffer[0..8].*);
}
