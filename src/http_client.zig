const std = @import("std");
const Allocator = std.mem.Allocator;

const MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB
const MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024; // 10MB

pub const HttpError = error{
    RequestFailed,
    InvalidResponse,
    NetworkError,
    AuthenticationError,
};

pub const HttpResponse = struct {
    status_code: u16,
    body: []u8,
    allocator: Allocator,

    pub fn deinit(self: *HttpResponse) void {
        self.allocator.free(self.body);
    }
};

pub const HttpClient = struct {
    client: std.http.Client,
    allocator: Allocator,

    pub fn init(allocator: Allocator) HttpClient {
        var client = std.http.Client{ .allocator = allocator };
        client.next_https_rescan_certs = true;
        return HttpClient{
            .client = client,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.client.deinit();
    }

    pub fn get(self: *HttpClient, url: []const u8, auth_header: ?[]const u8) !HttpResponse {
        return self.makeRequest(.GET, url, auth_header, null, null, null);
    }

    pub fn getWithHeaders(self: *HttpClient, url: []const u8, auth_header: ?[]const u8, extra_headers: []const std.http.Header) !HttpResponse {
        return self.makeRequestWithHeaders(.GET, url, auth_header, null, null, extra_headers);
    }

    pub fn post(self: *HttpClient, url: []const u8, auth_header: ?[]const u8, body: ?[]const u8) !HttpResponse {
        return self.makeRequest(.POST, url, auth_header, body, null, null);
    }

    pub fn postWithContentType(self: *HttpClient, url: []const u8, auth_header: ?[]const u8, body: ?[]const u8, content_type: []const u8) !HttpResponse {
        return self.makeRequest(.POST, url, auth_header, body, content_type, null);
    }

    fn makeRequest(self: *HttpClient, method: std.http.Method, url: []const u8, auth_header: ?[]const u8, body: ?[]const u8, content_type: ?[]const u8, extra_headers: ?[]const std.http.Header) !HttpResponse {
        return self.makeRequestWithHeaders(method, url, auth_header, body, content_type, extra_headers orelse &[_]std.http.Header{});
    }

    fn makeRequestWithHeaders(self: *HttpClient, method: std.http.Method, url: []const u8, auth_header: ?[]const u8, body: ?[]const u8, content_type: ?[]const u8, extra_headers: []const std.http.Header) !HttpResponse {
        const uri = std.Uri.parse(url) catch return HttpError.InvalidResponse;

        // Create headers array with enough space for all headers
        var headers_buffer: [10]std.http.Header = undefined;
        var headers_count: usize = 0;
        var content_length_buffer: [32]u8 = undefined;

        if (auth_header) |auth| {
            headers_buffer[headers_count] = .{ .name = "Authorization", .value = auth };
            headers_count += 1;
        }
        headers_buffer[headers_count] = .{ .name = "accept", .value = "application/json" };
        headers_count += 1;
        headers_buffer[headers_count] = .{ .name = "accept-encoding", .value = "gzip, deflate" };
        headers_count += 1;
        headers_buffer[headers_count] = .{ .name = "user-agent", .value = "Zig HTTP Client" };
        headers_count += 1;

        // Add extra headers
        for (extra_headers) |header| {
            if (headers_count >= headers_buffer.len) break;
            headers_buffer[headers_count] = header;
            headers_count += 1;
        }

        if (body) |b| {
            const ct = content_type orelse "application/json";
            if (headers_count < headers_buffer.len) {
                headers_buffer[headers_count] = .{ .name = "content-type", .value = ct };
                headers_count += 1;
            }

            const content_length_str = std.fmt.bufPrint(content_length_buffer[0..], "{d}", .{b.len}) catch return HttpError.InvalidResponse;
            if (headers_count < headers_buffer.len) {
                headers_buffer[headers_count] = .{ .name = "content-length", .value = content_length_str };
                headers_count += 1;
            }
        }

        // Create request options
        const request_options = std.http.Client.RequestOptions{
            .extra_headers = headers_buffer[0..headers_count],
            .keep_alive = true,
            .version = .@"HTTP/1.1",
        };

        var http_request = self.client.request(method, uri, request_options) catch return HttpError.NetworkError;
        defer http_request.deinit();

        if (body) |b| {
            try http_request.sendBodyComplete(@constCast(b));
        } else {
            try http_request.sendBodiless();
        }

        var redirect_buffer: [1024]u8 = undefined;
        var response = http_request.receiveHead(redirect_buffer[0..]) catch return HttpError.NetworkError;

        const status_code = @intFromEnum(response.head.status);

        var transfer_buffer: [4096]u8 = undefined;
        const body_reader = response.reader(transfer_buffer[0..]);

        // Read the raw response body
        const raw_body = body_reader.*.allocRemaining(self.allocator, std.Io.Limit.limited64(MAX_RESPONSE_SIZE)) catch return HttpError.InvalidResponse;

        // Check if response is gzipped
        var response_body: []u8 = undefined;
        if (raw_body.len >= 2 and raw_body[0] == 0x1f and raw_body[1] == 0x8b) {
            // Gzip compressed - decompress it
            response_body = try self.decompressGzip(raw_body);
            self.allocator.free(raw_body);
        } else {
            response_body = raw_body;
        }

        return HttpResponse{
            .status_code = status_code,
            .body = response_body,
            .allocator = self.allocator,
        };
    }

    fn decompressGzip(self: *HttpClient, compressed: []const u8) ![]u8 {
        // Verify gzip header
        if (compressed.len < 10) return HttpError.InvalidResponse;
        if (compressed[0] != 0x1f or compressed[1] != 0x8b) {
            return HttpError.InvalidResponse;
        }

        // Use gzip mode to let Zig handle the wrapper
        const window = try self.allocator.alloc(u8, std.compress.flate.max_window_len);
        defer self.allocator.free(window);

        var reader = std.Io.Reader.fixed(compressed);
        var decomp = std.compress.flate.Decompress.init(
            &reader,
            .gzip,
            window,
        );

        // Read all decompressed data
        const decompressed = try decomp.reader.allocRemaining(
            self.allocator,
            std.Io.Limit.limited64(MAX_DECOMPRESSED_SIZE),
        );

        return decompressed;
    }
};
