const std = @import("std");
const Blowfish = @import("Blowfish.zig");

pub fn BlowfishWriter(comptime WriterType: type) type {
    return struct {
        encrypted_writer: WriterType,
        blowfish: Blowfish,
        unencrypted_buffer: [8]u8 = .{0} ** 8,
        current_unencrypted: []u8 = &.{},

        pub const Error = WriterType.Error;
        pub const Writer = std.io.Writer(*Self, Error, write);

        const Self = @This();

        fn init(key: []const u8, w: WriterType) BlowfishWriter(WriterType) {
            return Self{
                .encrypted_writer = w,
                .blowfish = Blowfish.init(key),
            };
        }

        pub fn flush(self: *Self) !void {
            while (self.current_unencrypted.len > 0) {
                _ = try self.write(&.{0});
            }
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn writeABlock(self: *Self, source: []const u8) !void {
            var encrypted_buffer: [8]u8 = undefined;
            self.blowfish.encrypt(source, &encrypted_buffer);
            var wrote: usize = 0;
            while (wrote < 8) {
                wrote += try self.encrypted_writer.write(encrypted_buffer[wrote..8]);
            }
        }

        pub fn write(self: *Self, s: []const u8) Error!usize {
            var source = s;

            if (self.current_unencrypted.len > 0) {
                const to_copy = @min(8 - self.current_unencrypted.len, source.len);
                @memcpy(self.unencrypted_buffer[self.current_unencrypted.len .. self.current_unencrypted.len + to_copy], source[0..to_copy]);
                self.current_unencrypted = self.unencrypted_buffer[0 .. self.current_unencrypted.len + to_copy];
                if (self.current_unencrypted.len < 8) {
                    return s.len;
                } else {
                    try self.writeABlock(self.current_unencrypted);
                    self.current_unencrypted = self.unencrypted_buffer[0..0];
                    source = source[to_copy..];
                }
            }

            while (source.len >= 8) {
                try self.writeABlock(source[0..8]);
                source = source[8..];
            }
            if (source.len > 0) {
                @memcpy(self.unencrypted_buffer[0..source.len], source);
                self.current_unencrypted = self.unencrypted_buffer[0..source.len];
            }
            return s.len;
        }

        pub fn encrypt(self: *Self, reader: anytype) !void {
            var buf: [1024]u8 = undefined;
            while (true) {
                const ct = try reader.read(&buf);
                if (ct == 0) {
                    break;
                }
                try self.writer().writeAll(buf[0..ct]);
            }
            try self.flush();
        }
    };
}

pub fn blowfishWriter(key: []const u8, underlying_stream: anytype) BlowfishWriter(@TypeOf(underlying_stream)) {
    return BlowfishWriter(@TypeOf(underlying_stream)).init(key, underlying_stream);
}

test "writer" {
    const alloc = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(alloc);
    var bfwriter = blowfishWriter("TESTKEY", buffer.writer(alloc));

    const unencrypted: [8]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    const wrote = try bfwriter.write(&unencrypted);
    try bfwriter.flush();

    try std.testing.expectEqual(wrote, 8);
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(&encrypted, buffer.items);
}

test "weird buffer lengths" {
    const alloc = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(alloc);
    var bfwriter = blowfishWriter("TESTKEY", buffer.writer(alloc));

    const unencrypted: [8]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    var wrote = try bfwriter.write(unencrypted[0..3]);
    wrote += try bfwriter.write(unencrypted[3..]);
    try bfwriter.flush();

    try std.testing.expectEqual(wrote, 8);
    const encrypted: [8]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(&encrypted, buffer.items);
}

test "more weird buffer lengths" {
    const alloc = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(alloc);
    var bfwriter = blowfishWriter("TESTKEY", buffer.writer(alloc));

    const unencrypted: [16]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };
    var wrote = try bfwriter.write(unencrypted[0..3]);
    try std.testing.expectEqual(0, buffer.items.len);
    wrote += try bfwriter.write(unencrypted[3..10]);
    try std.testing.expectEqual(8, buffer.items.len);
    wrote += try bfwriter.write(unencrypted[10..]);
    try std.testing.expectEqual(16, buffer.items.len);
    try bfwriter.flush();

    try std.testing.expectEqual(wrote, 16);
    const encrypted: [16]u8 = .{ 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4, 0xDF, 0x33, 0x3F, 0xD2, 0x30, 0xA7, 0x1B, 0xB4 };
    try std.testing.expectEqualDeep(&encrypted, buffer.items);
}

test "padding" {
    const alloc = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(alloc);
    var bfwriter = blowfishWriter("TESTKEY", buffer.writer(alloc));

    const unencrypted: [5]u8 = .{ 0x00, 0x00, 0x00, 0x01, 0x00 };
    const wrote = try bfwriter.write(&unencrypted);
    try std.testing.expectEqual(wrote, 5);
    try std.testing.expectEqual(0, buffer.items.len);
    try bfwriter.flush();
    try std.testing.expectEqual(8, buffer.items.len);

    const encrypted: [8]u8 = .{ 0x6c, 0x44, 0xdc, 0xed, 0x6c, 0xa6, 0x34, 0x79 };
    try std.testing.expectEqualDeep(&encrypted, buffer.items);
}
