const std = @import("std");
const io = std.io;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const Blowfish = @import("Blowfish.zig");

pub fn BlowfishReader(comptime ReaderType: type) type {
    return struct {
        encrypted_reader: ReaderType,
        decrypted_buffer: [8]u8 = .{0} ** 8,
        current_decrypted: []u8 = &.{},
        blowfish: Blowfish,

        pub const Error = ReaderType.Error || error{UnevenBytesInStream};
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        fn init(key: []const u8, r: ReaderType) BlowfishReader(ReaderType) {
            return Self{
                .encrypted_reader = r,
                .blowfish = Blowfish.init(key),
            };
        }

        pub fn decrypt(self: *Self, writer: anytype) !void {
            var buf: [1024]u8 = undefined;
            while (true) {
                const n = try self.read(buf[0..]);
                if (n == 0) {
                    break;
                }
                try writer.writeAll(buf[0..n]);
            }
        }

        inline fn read8(self: *Self, buf: []u8) Error!bool {
            var n: usize = 0;
            while (n < 8) {
                const ct = try self.encrypted_reader.read(buf[n..8]);
                if (ct == 0) {
                    if (n > 0) {
                        return error.UnevenBytesInStream;
                    } else {
                        return false; // natural EOF
                    }
                }
                n += ct;
            }
            return true;
        }

        pub fn read(self: *Self, d: []u8) Error!usize {
            var dest = d;
            var count: usize = 0;
            // First try reading from the already buffered data onto the destination.
            if (self.current_decrypted.len != 0) {
                count = @min(self.current_decrypted.len, dest.len);
                @memcpy(dest[0..count], self.current_decrypted[0..count]);
                self.current_decrypted = self.current_decrypted[count..];
                dest = dest[count..];
            }
            var encrypted_buffer: [8]u8 = undefined;
            while (dest.len >= 8) {
                if (!try self.read8(encrypted_buffer[0..])) {
                    return count;
                }
                self.blowfish.decrypt(encrypted_buffer[0..], self.decrypted_buffer[0..]);
                @memcpy(dest[0..8], self.decrypted_buffer[0..]);
                dest = dest[8..];
                count += 8;
            }
            if (dest.len > 0) {
                if (!try self.read8(encrypted_buffer[0..8])) {
                    return count;
                }
                self.blowfish.decrypt(encrypted_buffer[0..], self.decrypted_buffer[0..]);
                @memcpy(dest, self.decrypted_buffer[0..dest.len]);
                self.current_decrypted = self.decrypted_buffer[dest.len..];
                count += dest.len;
            }
            return count;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn blowfishReader(key: []const u8, reader: anytype) BlowfishReader(@TypeOf(reader)) {
    return BlowfishReader(@TypeOf(reader)).init(key, reader);
}

test "memory reader" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var reader = std.io.fixedBufferStream(encrypted[0..8]);
    var bf_reader = blowfishReader(key, reader.reader());
    var decrypted: [8]u8 = undefined;
    const n = try bf_reader.read(decrypted[0..]);
    try std.testing.expectEqual(n, 8);
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 }, decrypted);
}

test "memory reader short read" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var reader = std.io.fixedBufferStream(encrypted[0..]);
    var bf_reader = blowfishReader(key, reader.reader());
    var decrypted: [1]u8 = undefined;
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x01}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x00}, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{0x02}, decrypted);
}

test "memory reader overlapping read" {
    const key = "TESTKEY";
    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var reader = std.io.fixedBufferStream(encrypted[0..]);
    var bf_reader = blowfishReader(key, reader.reader());
    var decrypted: [3]u8 = undefined;
    try std.testing.expectEqual(3, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x01, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x02, 0x00 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x01 }, decrypted);
    try std.testing.expectEqual(3, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqual(0x02, decrypted[0]);
    try std.testing.expectEqual(0, try bf_reader.read(decrypted[0..]));
}

test "memory reader big buffer" {
    const key = "TESTKEY";
    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    var reader = std.io.fixedBufferStream(encrypted[0..]);
    var bf_reader = blowfishReader(key, reader.reader());
    var decrypted: [15]u8 = undefined;
    try std.testing.expectEqual(15, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }, decrypted);
    try std.testing.expectEqual(1, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqual(0x02, decrypted[0]);
}

test "read padded" {
    const key = "TESTKEY";
    const encrypted: [8]u8 = .{ 0x6c, 0x44, 0xdc, 0xed, 0x6c, 0xa6, 0x34, 0x79 };
    var reader = std.io.fixedBufferStream(encrypted[0..]);
    var bf_reader = blowfishReader(key, reader.reader());
    var decrypted: [8]u8 = undefined;
    try std.testing.expectEqual(8, try bf_reader.read(decrypted[0..]));
    try std.testing.expectEqualDeep(.{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, decrypted);
}
