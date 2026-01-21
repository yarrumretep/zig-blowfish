const std = @import("std");
const flags = @import("flags");
const BlowfishReader = @import("BlowfishReader.zig");
const BlowfishWriter = @import("BlowfishWriter.zig");

const Error = error{KeyRequired};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(gpa.allocator());
    defer std.process.argsFree(gpa.allocator(), args);

    const options = flags.parse(args, "blowfish", Flags, .{});

    var key: []const u8 = undefined;

    if (options.key) |k| {
        key = k;
    } else if (options.keyfile) |kf| {
        var file = try std.fs.cwd().openFile(kf, .{});
        defer file.close();

        key = try file.readToEndAlloc(gpa.allocator(), 4096);
    } else {
        return Error.KeyRequired;
    }
    defer if (options.keyfile) |_| {
        gpa.allocator().free(key);
    };

    // Buffers for file I/O
    var file_read_buf: [4096]u8 = undefined;
    var file_write_buf: [4096]u8 = undefined;
    var bf_buf: [4096]u8 = undefined;

    // Get input file/stdin
    var infile: std.fs.File = undefined;
    var in_reader: std.fs.File.Reader = undefined;
    if (options.infile) |fname| {
        infile = try std.fs.cwd().openFile(fname, .{});
        in_reader = infile.readerStreaming(&file_read_buf);
    } else {
        infile = std.fs.File.stdin();
        in_reader = infile.readerStreaming(&file_read_buf);
    }
    defer if (options.infile) |_| {
        infile.close();
    };

    // Get output file/stdout
    var outfile: std.fs.File = undefined;
    var out_writer: std.fs.File.Writer = undefined;
    if (options.outfile) |fname| {
        outfile = try std.fs.cwd().createFile(fname, .{ .truncate = true });
        out_writer = outfile.writerStreaming(&file_write_buf);
    } else {
        outfile = std.fs.File.stdout();
        out_writer = outfile.writerStreaming(&file_write_buf);
    }
    defer {
        // Flush writer before closing
        out_writer.interface.flush() catch {};
        if (options.outfile) |_| {
            outfile.close();
        }
    }

    switch (options.positional.operation) {
        .encrypt => {
            var bfwriter = BlowfishWriter.blowfishWriter(key, &out_writer.interface, &bf_buf);
            try bfwriter.encryptAll(&in_reader.interface);
        },
        .decrypt => {
            var bfreader = BlowfishReader.blowfishReader(key, &in_reader.interface, &bf_buf);
            try bfreader.decryptAll(&out_writer.interface);
        },
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
