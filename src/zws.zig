const std = @import("std");
const net = std.net;
const proto = std.http.protocol;
const base64 = std.base64;
const HttpRequest = std.http.Server.Request;
const Allocator = std.mem.Allocator;
const Sha1 = std.crypto.hash.Sha1;
const ArrayList = std.ArrayList;
const io = std.io;

pub const Message = struct {
    content: []const u8,
    type: MessageType,
    final: bool,
};

pub const MessageType = enum {
    Binary,
    Text,
    Ping,
    Pong,
};

test {
    _ = FixedBuffer(69);
}

fn FixedBuffer(comptime buffer_size: usize) type {
    return struct {
        buffer: [buffer_size]u8 = undefined,
        begin: usize = 0,
        limit: usize = 0,

        const Self = @This();

        pub fn load_percentage(self: Self) u8 {
            return @intCast(u8, @divFloor(self.end() * 100, buffer_size));
        }

        pub fn taken_const(self: Self) []const u8 {
            return self.buffer[self.begin..self.end()];
        }

        pub fn taken(self: *Self) []u8 {
            return self.buffer[self.begin..self.end()];
        }

        pub fn free(self: *Self) []u8 {
            @memset(self.buffer[0..self.begin], undefined);
            @memset(self.buffer[self.end()..], undefined);
            return self.buffer[self.end()..];
        }

        fn end(self: Self) usize {
            return self.begin + self.limit;
        }

        pub fn shrink(self: *Self, n: usize) void {
            std.debug.assert(self.begin + n <= self.end());
            self.begin += n;
            self.limit -= n;
        }

        pub fn grow(self: *Self, n: usize) void {
            std.debug.assert(self.end() + n <= buffer_size);
            self.limit += n;
        }

        pub fn rewind(self: *Self) void {
            if (self.limit < self.begin) {
                @memcpy(self.buffer[0..self.limit], self.buffer[self.begin..self.end()]);
            } else {
                std.mem.copyForwards(u8, self.buffer[0..self.limit], self.buffer[self.begin..self.end()]);
            }
            self.begin = 0;
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) std.os.WriteError!void {
            try writer.print("FixedBuffer{{ [0 - {}][ ", .{self.begin});

            try writer.print("{s}", .{std.fmt.fmtSliceHexLower(self.taken_const())});

            try writer.print("][{} - {}] }}", .{ self.end(), buffer_size });
        }
    };
}

pub fn WebSocket(comptime buffer_size: usize) type {
    comptime {
        const minimum_buffer_size = 1 << 5;
        if (buffer_size < minimum_buffer_size) {
            @compileError(std.fmt.comptimePrint(
                "The buffer size for the websocket is too small, minimum is {}.\n" ++
                    "Be aware that a smaller size may result in extra reads.",
                .{
                    minimum_buffer_size,
                },
            ));
        }
    }

    return struct {
        is_closed: bool = false,
        stream: std.net.Stream,
        buffer: FixedBuffer(buffer_size) = .{},

        base_header: ?protocol.BaseHeader = null,
        extra_header: ?protocol.ExtraHeader = null,
        payload_cursor: usize = 0,

        const Self = @This();

        pub fn init(stream: std.net.Stream) Self {
            return .{
                .stream = stream,
            };
        }

        pub fn send(self: Self, comptime opcode: protocol.Opcode, payload: []const u8) !void {
            switch (opcode) {
                .Text, .Binary => {
                    const frame = protocol.Frame.message(opcode, payload);
                    var buffer: [buffer_size]u8 = undefined;
                    const encoded_frame = try frame.encode(&buffer);
                    _ = try self.stream.write(encoded_frame);
                },
                else => {
                    @compileError("Only Text and Binary opcodes are allowed");
                },
            }
        }

        fn getOrReadBaseHeader(self: *Self) ?protocol.BaseHeader {
            if (self.base_header) |base_header| {
                return base_header;
            } else {
                if (protocol.BaseHeader.decode(self.buffer.taken())) |base_header| {
                    self.buffer.shrink(base_header.encodedSize());
                    self.base_header = base_header;
                    return base_header;
                } else {
                    return null;
                }
            }
        }

        fn getOrReadExtraHeader(self: *Self, base_header: protocol.BaseHeader) ?protocol.ExtraHeader {
            if (self.extra_header) |extra_header| {
                return extra_header;
            } else {
                if (protocol.ExtraHeader.decode(base_header, self.buffer.taken())) |extra_header| {
                    self.buffer.shrink(protocol.ExtraHeader.encodedSize(base_header));
                    self.extra_header = extra_header;
                    return extra_header;
                } else {
                    return null;
                }
            }
        }

        fn missingPayloadLength(self: Self, extra_header: protocol.ExtraHeader) usize {
            return extra_header.payload_length - self.payload_cursor;
        }

        fn getOrReadPayload(self: *Self, extra_header: protocol.ExtraHeader) []u8 {
            const missing_payload_length = self.missingPayloadLength(extra_header);
            var taken_buffer = self.buffer.taken();
            const available_length = if (missing_payload_length <= taken_buffer.len)
                missing_payload_length
            else
                taken_buffer.len;

            var payload = taken_buffer[0..available_length];
            self.buffer.shrink(payload.len);

            for (payload) |*chr| {
                chr.* ^= extra_header.mask_key[@mod(self.payload_cursor, 4)];
                self.payload_cursor += 1;
            }

            return payload;
        }

        pub fn recv_raww(self: *Self) ![]u8 {
            while (true) {
                blk: {
                    if (self.buffer.load_percentage() > 50) {
                        self.buffer.rewind();
                    }
                    {
                        const nread = try self.stream.read(self.buffer.free());
                        self.buffer.grow(nread);
                    }

                    const base_header = self.getOrReadBaseHeader() orelse break :blk;
                    const extra_header = self.getOrReadExtraHeader(base_header) orelse break :blk;
                    const payload = self.getOrReadPayload(extra_header);

                    if (self.missingPayloadLength(extra_header) == 0) {
                        self.base_header = null;
                        self.extra_header = null;
                        self.payload_cursor = 0;
                    }

                    return payload;
                }
            }
        }

        fn recv_raw(self: *Self) !protocol.Frame {
            {
                const nread = try self.stream.read(self.buffer.free());
                self.buffer.grow(nread);
            }
            defer self.buffer.shrink(self.buffer.taken().len);
            return protocol.Frame.decode(self.buffer.taken());
        }

        pub fn recv(self: *Self) ![]const u8 {
            return try self.recv_raww();
            //const frame = try self.recv_raww();
            //return frame.payload;
        }
    };
}

pub const protocol = struct {
    const Opcode = enum(u4) {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA,
    };

    const BaseHeader = packed struct {
        opcode: Opcode,
        rsv: u3 = 0,
        fin: bool = true,

        payload_length: u7 = 0,
        mask: bool = false,

        const Self = @This();

        pub fn encode(self: Self) [2]u8 {
            return @bitCast([2]u8, self);
        }

        pub fn decode(bytes: []u8) ?Self {
            if (bytes.len >= @sizeOf(@This())) {
                return @bitCast(Self, bytes[0..2].*);
            } else {
                return null;
            }
        }

        pub fn encodedSize(self: Self) usize {
            _ = self;
            return @sizeOf(@This());
        }

        comptime {
            std.debug.assert(@mod(@bitSizeOf(@This()), 16) == 0);
        }
    };

    const ExtraHeader = struct {
        mask_key: [4]u8,
        payload_length: usize,

        const Self = @This();

        pub fn decode(base_header: BaseHeader, bytes: []u8) ?Self {
            if (bytes.len >= encodedSize(base_header)) {
                var sliding_bytes = bytes;

                const payload_length: usize = blk: {
                    switch (base_header.payload_length) {
                        126 => {
                            defer sliding_bytes = sliding_bytes[2..];
                            break :blk @byteSwap(@bitCast(u16, bytes[0..2].*));
                        },
                        127 => {
                            defer sliding_bytes = sliding_bytes[8..];
                            break :blk @byteSwap(@bitCast(u64, sliding_bytes[0..8].*));
                        },
                        else => |length| break :blk length,
                    }
                };

                var mask_key: [4]u8 = [_]u8{0} ** 4;
                if (base_header.mask) {
                    mask_key = sliding_bytes[0..4].*;
                }

                return .{ .mask_key = mask_key, .payload_length = payload_length };
            } else {
                return null;
            }
        }

        pub fn encodedSize(base_header: BaseHeader) usize {
            var size: usize = 0;
            if (base_header.mask) {
                size += 4;
            }
            switch (base_header.payload_length) {
                126 => size += 2,
                127 => size += 8,
                else => {},
            }
            return size;
        }
    };

    const BaseFrame = packed struct {
        opcode: Opcode,
        rsv: u3 = 0,
        fin: bool = true,

        payload_length: u7 = 0,
        mask: bool = false,

        const Self = @This();

        pub fn encode(self: Self) [2]u8 {
            return @bitCast([2]u8, self);
        }

        pub fn decode(bytes: [2]u8) Self {
            return @bitCast(Self, bytes);
        }

        comptime {
            std.debug.assert(@mod(@bitSizeOf(@This()), 16) == 0);
        }
    };

    pub const Frame = struct {
        base: BaseFrame,
        mask_key: [4]u8 = undefined,
        payload: []const u8 = &.{},

        const Self = @This();

        pub fn decode(frame: []u8) Frame {
            std.debug.assert(frame.len >= 2);

            const base = @bitCast(BaseFrame, frame[0..2].*);
            std.debug.assert(base.payload_length < 126);

            const payload_offset: usize = if (base.mask) 6 else 2;
            var payload = frame[payload_offset .. payload_offset + base.payload_length];

            var mask_key: [4]u8 = undefined;
            if (base.mask) {
                mask_key = frame[2..6].*;
                for (payload, 0..) |*chr, i| {
                    chr.* ^= mask_key[@mod(i, 4)];
                }
            }

            return .{
                .base = base,
                .mask_key = mask_key,
                .payload = payload,
            };
        }

        fn payloadOffset(self: Self) usize {
            return if (self.base.mask) 6 else 2;
        }

        fn payloadLength(self: Self) usize {
            return @as(usize, self.base.payload_length);
        }

        pub fn encodedSize(self: Self) usize {
            return self.payloadOffset() + self.base.payload_length;
        }

        pub fn encode(self: Self, buffer: []u8) ![]u8 {
            buffer[0..2].* = self.base.encode();

            var payload = buffer[self.payloadOffset()..(self.payloadOffset() + self.payloadLength())];
            @memcpy(payload, self.payload);

            if (self.base.mask) {
                buffer[2..6].* = self.mask_key;
                for (payload, 0..) |*chr, i| {
                    chr.* ^= self.mask_key[@mod(i, 4)];
                }
            }

            return buffer[0..self.encodedSize()];
        }

        pub fn encodeAlloc(self: Self, allocator: Allocator) ![]u8 {
            var buffer = try allocator.alloc(u8, self.encodedSize());
            errdefer allocator.free(buffer);
            return self.encode(buffer);
        }

        pub fn message(comptime opcode: Opcode, payload: []const u8) Frame {
            std.debug.assert(payload.len < 126);
            switch (opcode) {
                .Ping, .Pong, .Text, .Binary => return .{
                    .base = .{ .fin = true, .opcode = opcode, .payload_length = @intCast(u7, payload.len) },
                    .payload = payload,
                },
                else => @compileError("Opcode not valid here"),
            }
        }

        pub fn control(comptime opcode: Opcode) Frame {
            switch (opcode) {
                .Ping, .Pong, .Close => return .{
                    .base = .{ .fin = true, .opcode = opcode },
                },
                else => @compileError("Only opcodes for control frames are allowed here."),
            }
        }

        pub fn eql(self: Self, other: Frame) bool {
            return std.meta.eql(self.base, other.base) and
                (if (self.base.mask) std.mem.eql(u8, &self.mask_key, &other.mask_key) else true) and
                std.mem.eql(u8, self.payload, other.payload);
        }

        pub fn format(self: Self, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) std.os.WriteError!void {
            try writer.print("Frame{{ {s}{s}[{s}] ({} bytes) '{s}' }}", .{
                if (self.base.fin) "[FIN]" else "",
                if (self.base.mask) "[MASKED]" else "",
                @tagName(self.base.opcode),
                self.base.payload_length,
                self.payload,
            });
        }
    };
};

fn testFrameEncoding(allocator: Allocator, frame: protocol.Frame, bytes: []const u8) void {
    var b = allocator.dupe(u8, bytes) catch unreachable;
    defer allocator.free(b);
    var obtained: []const u8 = frame.encodeAlloc(allocator) catch unreachable;
    defer allocator.free(obtained);
    if (!std.mem.eql(u8, obtained, b)) {
        std.debug.print("Unexpected encoding for frame\nExpected: 0x{s} {}\nObtained: 0x{s}\n", .{
            std.fmt.fmtSliceHexLower(bytes),
            frame,
            std.fmt.fmtSliceHexLower(obtained),
        });
        unreachable;
    }
}

fn testFrameDecoding(allocator: Allocator, frame: protocol.Frame, bytes: []const u8) void {
    var b = allocator.dupe(u8, bytes) catch unreachable;
    defer allocator.free(b);
    var obtained = protocol.Frame.decode(b);
    if (!frame.eql(obtained)) {
        std.debug.print("Unexpected decoding for frame\nExpected: {any}\nObtained: {any}\n", .{ frame, obtained });
        unreachable;
    }
}

// Taken from RFC 6455, Section 5.7.  Examples
test "Encoding and decoding frames" {
    var allocator = std.testing.allocator;
    // A single-frame unmasked text message
    {
        const frame = protocol.Frame.message(.Text, "Hello");
        const bytes = [7]u8{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
        testFrameEncoding(allocator, frame, &bytes);
        testFrameDecoding(allocator, frame, &bytes);
    }

    // A single-frame masked text message
    {
        var frame = protocol.Frame.message(.Text, "Hello");
        const bytes = [11]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
        frame.base.mask = true;
        frame.mask_key = (&bytes)[2..6].*;
        testFrameEncoding(allocator, frame, &bytes);
        testFrameDecoding(allocator, frame, &bytes);
    }

    // TODO: A fragmented unmasked text message

    // Unmasked Ping request and masked Ping response
    {
        var frame = protocol.Frame.message(.Ping, "Hello");
        const bytes = [7]u8{ 0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
        testFrameEncoding(allocator, frame, &bytes);
        testFrameDecoding(allocator, frame, &bytes);
    }
    {
        var frame = protocol.Frame.message(.Pong, "Hello");
        const bytes = [11]u8{ 0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
        frame.base.mask = true;
        frame.mask_key = (&bytes)[2..6].*;
        testFrameEncoding(allocator, frame, &bytes);
        testFrameDecoding(allocator, frame, &bytes);
    }

    // TODO: 256 bytes binary message in a single unmasked frame

    // TODO: 64KiB binary message in a single unmasked frame
}
