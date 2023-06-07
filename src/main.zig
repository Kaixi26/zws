const std = @import("std");
const net = std.net;
const proto = std.http.protocol;
const base64 = std.base64;
const HttpRequest = std.http.Server.Request;
const Allocator = std.mem.Allocator;
const Sha1 = std.crypto.hash.Sha1;
const ArrayList = std.ArrayList;

const zws = @import("zws.zig");
const protocol = zws.protocol;
const WebSocket = zws.WebSocket(69);

const minimal_http_response_str =
    \\HTTP/1.1 200 OK
    \\Content-Length: 12
    \\Content-Type: text/plain; charset=utf-8
    \\
    \\Hello World!
;

pub fn main() !void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = general_purpose_allocator.allocator();

    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();

    _ = try server.listen(net.Address.parseIp("127.0.0.1", 3000) catch unreachable);
    std.debug.print("listening at {}\n", .{server.listen_address});

    {
        var conn = try server.accept();
        defer conn.stream.close();

        std.debug.print("accepted client {}\n", .{conn.address});

        var buf: [1024]u8 = undefined;
        const bytes_read = try conn.stream.read(&buf);
        const payload = buf[0..bytes_read];

        var request = HttpRequest{
            .version = undefined,
            .method = undefined,
            .target = undefined,
            .headers = .{ .allocator = allocator, .owned = true },
            .parser = proto.HeadersParser.initDynamic(6969),
        };
        try request.parse(payload);
        defer request.headers.deinit();

        std.debug.print("\n---------\nRequest:\n{s}\n", .{payload});

        if (computeWebsocketResponse(allocator, request)) |response| {
            defer allocator.free(response);
            {
                const written = try conn.stream.write(response);
                std.debug.print("\n---------\nResponse ({} bytes):\n{s}\n", .{ written, response });
            }

            std.os.nanosleep(1, 0);

            var ws = WebSocket.init(conn.stream);
            const hello = "hello world";
            try ws.send(.Text, hello);

            while (true) {
                const resp = try ws.recv();

                std.debug.print("recv {s}\n", .{resp});
            }

            std.os.nanosleep(69, 0);
        } else |err| {
            std.debug.print("\n---------\nResponse:\n{any}\n", .{err});
            _ = try conn.stream.write(minimal_http_response_str);
        }
    }
}

const InvalidWebsocketRequest = error{
    InvalidConnectionHeader,
    InvalidUpgradeHeader,
    InvalidWebsocketKeyHeader,
    InvalidWebsocketVersionHeader,
};

const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub fn computeWebsocketResponse(allocator: Allocator, request: HttpRequest) ![]u8 {
    blk: {
        var opt_values = try request.headers.getValues(allocator, "Connection");
        if (opt_values) |values| {
            for (values) |value| {
                if (std.mem.containsAtLeast(u8, value, 1, "Upgrade")) {
                    break :blk;
                }
            }
        }
        return error.InvalidConnectionHeader;
    }
    if (request.headers.getFirstEntry("Upgrade")) |header_upgrade| {
        if (!std.mem.eql(u8, header_upgrade.value, "websocket")) {
            return error.InvalidUpgradeHeader;
        }
    }
    if (request.headers.getFirstEntry("Sec-WebSocket-Version")) |header_upgrade| {
        if (!std.mem.eql(u8, header_upgrade.value, "13")) {
            return error.InvalidWebsocketVersionHeader;
        }
    }
    if (request.headers.getFirstEntry("Sec-WebSocket-Key")) |header_websocket_key| {
        var buf = ArrayList(u8).init(allocator);
        defer buf.deinit();
        const response_key = try computeWebsocketResponseKey(&buf, header_websocket_key.value);
        var response = try std.fmt.allocPrint(allocator, "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n", .{response_key});
        return response;
    } else return error.InvalidWebsocketKeyHeader;
}

pub fn computeWebsocketResponseKey(buf: *ArrayList(u8), websocket_key: []const u8) ![]const u8 {
    var digest: [Sha1.digest_length]u8 = undefined;
    var h = std.crypto.hash.Sha1.init(.{});
    h.update(websocket_key);
    h.update(websocket_guid);
    h.final(&digest);

    var encoder = base64.Base64Encoder.init(base64.standard_alphabet_chars, '=');
    var expected_capacity = encoder.calcSize(digest.len);

    try buf.ensureTotalCapacity(expected_capacity);
    try buf.appendNTimes(undefined, expected_capacity);

    return encoder.encode(buf.items, &digest);
}

test {
    var allocator = std.testing.allocator;
    var buf = ArrayList(u8).init(allocator);
    defer buf.deinit();

    var websocket_request_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var websocket_response_key = try computeWebsocketResponseKey(&buf, websocket_request_key);
    const expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
    if (!std.mem.eql(u8, expected, websocket_response_key)) {
        std.debug.print("Expected: {s}\n", .{expected});
        std.debug.print("Obtained: {s}\n", .{websocket_response_key});
        unreachable;
    }
}
