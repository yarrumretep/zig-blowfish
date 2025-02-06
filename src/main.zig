const std = @import("std");
const flags = @import("flags");
const BlowfishReader = @import("BlowfishReader.zig");
const BlowfishWriter = @import("BlowfishWriter.zig");

const Error = error{KeyRequired};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var args = try std.process.argsWithAllocator(gpa.allocator());
    defer args.deinit();

    const options = flags.parseOrExit(&args, "blowfish", Flags, .{});

    var key: []const u8 = undefined;
    var in = std.io.getStdIn().reader();
    var out = std.io.getStdOut().writer();

    if (options.key) |k| {
        key = k;
    } else if (options.keyfile) |kf| {
        var file = try std.fs.cwd().openFile(kf, .{});
        defer file.close();

        key = try file.readToEndAlloc(gpa.allocator(), 4096);
        defer gpa.allocator().free(key);
    } else {
        std.debug.print("Either key or keyfile must be specified\n", .{});
        return Error.KeyRequired;
    }

    if (options.infile) |infile| {
        const file = try std.fs.cwd().openFile(infile, .{});
        defer file.close();
        in = file.reader();
    }

    if (options.outfile) |outfile| {
        const file = try std.fs.cwd().createFile(outfile, .{ .truncate = true });
        defer file.close();
        out = file.writer();
    }

    if (options.positional.operation == .encrypt) {
        var writer = BlowfishWriter.blowfishWriter(key, out);
        try writer.encrypt(in);
    } else {
        var reader = BlowfishReader.blowfishReader(key, in);
        try reader.decrypt(out);
    }
}

const Flags = struct {
    pub const description =
        \\This is a simple Blowfish encryption / decryption program
    ;

    pub const descriptions = .{
        .key = "Specify inline key value",
        .keyfile = "Read key from the specified file",
        .infile = "File to read from",
        .outfile = "File to write to",
    };

    key: ?[]const u8,
    keyfile: ?[]const u8,
    infile: ?[]const u8,
    outfile: ?[]const u8,

    positional: struct {
        operation: enum {
            encrypt,
            decrypt,
        },
        pub const descriptions = .{
            .operation = "encrypt / decrypt to specify the operation",
        };
    },

    pub const switches = .{
        .infile = 'i',
        .outfile = 'o',
        .key = 'k',
        .keyfile = 'f',
    };
};
