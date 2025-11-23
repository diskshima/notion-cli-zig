const std = @import("std");
const Allocator = std.mem.Allocator;

const MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB
const MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024; // 10MB

const HeaderBuilder = struct {
    headers: std.ArrayList(std.http.Header),
    content_length_buffer: [32]u8,
    allocator: Allocator,

    fn init() HeaderBuilder {
        const allocator = std.heap.page_allocator;
        const header_array = std.ArrayList(std.http.Header).initCapacity(allocator, 8) catch @panic("Failed to initialize header array");

        return .{
            .headers = header_array,
            .content_length_buffer = undefined,
            .allocator = allocator,
        };
    }

    fn add(self: *HeaderBuilder, name: []const u8, value: []const u8) !void {
        try self.headers.append(self.allocator, .{ .name = name, .value = value });
    }

    fn addAuth(self: *HeaderBuilder, auth: []const u8) !void {
        try self.add("Authorization", auth);
    }

    fn addContentType(self: *HeaderBuilder, content_type: []const u8) !void {
        try self.add("content-type", content_type);
    }

    fn addContentLength(self: *HeaderBuilder, length: usize) !void {
        const length_str = std.fmt.bufPrint(&self.content_length_buffer, "{d}", .{length}) catch return HttpError.InvalidResponse;
        try self.add("content-length", length_str);
    }

    fn build(self: HeaderBuilder) []const std.http.Header {
        return self.headers.items;
    }

    fn deinit(self: *HeaderBuilder) void {
        self.headers.deinit();
    }
};

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

        var builder = HeaderBuilder.init();

        // Add authentication header if provided
        if (auth_header) |auth| {
            try builder.addAuth(auth);
        }

        // Add standard headers
        try builder.add("accept", "application/json");
        try builder.add("accept-encoding", "gzip, deflate");
        try builder.add("user-agent", "Zig HTTP Client");

        // Add extra headers
        for (extra_headers) |header| {
            try builder.add(header.name, header.value);
        }

        // Add body-related headers if body is present
        if (body) |b| {
            const ct = content_type orelse "application/json";
            try builder.addContentType(ct);
            try builder.addContentLength(b.len);
        }

        // Create request options
        const request_options = std.http.Client.RequestOptions{
            .extra_headers = builder.build(),
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
