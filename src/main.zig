const std = @import("std");
const http_client = @import("http_client.zig");
const block_formatter = @import("block_formatter.zig");

const PAGE_ID_LENGTH = 32;

const NotionConfig = struct {
    api_base: []const u8 = "https://api.notion.com/v1",
    api_version: []const u8 = "2022-06-28",

    pub fn buildBlockUrl(self: NotionConfig, allocator: std.mem.Allocator, block_id: []const u8) ![]const u8 {
        return std.fmt.allocPrint(
            allocator,
            "{s}/blocks/{s}/children",
            .{ self.api_base, block_id },
        );
    }
};

const notion_config = NotionConfig{};

const NotionError = error{
    InvalidPageId,
    MissingApiToken,
    ApiRequestFailed,
    InvalidResponse,
};

fn isHexString(s: []const u8) bool {
    for (s) |c| {
        const is_hex_digit = (c >= '0' and c <= '9') or
            (c >= 'a' and c <= 'f') or
            (c >= 'A' and c <= 'F');
        if (!is_hex_digit) return false;
    }
    return true;
}

fn isNotionUrl(input: []const u8) bool {
    return std.mem.indexOf(u8, input, "notion.so/") != null;
}

fn cleanUrlPath(input: []const u8) ![]const u8 {
    const notion_prefix = "notion.so/";
    const prefix_idx = std.mem.indexOf(u8, input, notion_prefix) orelse return NotionError.InvalidPageId;
    const after_prefix = input[prefix_idx + notion_prefix.len ..];

    // Remove query parameters if present
    var query_iter = std.mem.splitScalar(u8, after_prefix, '?');
    const id_part = query_iter.next() orelse return NotionError.InvalidPageId;

    // Remove trailing slash if present
    var end = id_part.len;
    while (end > 0 and id_part[end - 1] == '/') {
        end -= 1;
    }

    return id_part[0..end];
}

fn findPageIdInPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    // The format could be:
    // 1. "workspace-name/2a9f69455b3080c88458f7ff164a5455" (with slash and workspace)
    // 2. "workspace-name-2a9f69455b3080c88458f7ff164a5455" (with hyphens)
    // 3. "2a9f69455b3080c88458f7ff164a5455" (just ID)

    // First, try splitting by slash (workspace/id format)
    if (std.mem.indexOf(u8, path, "/")) |slash_idx| {
        const potential_id = path[slash_idx + 1 ..];
        if (potential_id.len == PAGE_ID_LENGTH) {
            return try allocator.dupe(u8, potential_id);
        }
    }

    // Otherwise, look for the last segment that looks like a 32-char hex ID
    var segments = std.mem.splitBackwardsScalar(u8, path, '-');
    while (segments.next()) |segment| {
        if (segment.len == PAGE_ID_LENGTH and isHexString(segment)) {
            return try allocator.dupe(u8, segment);
        }
    }

    // If no 32-char segment found, return the whole thing
    return try allocator.dupe(u8, path);
}

fn printApiError(status_code: u16, response_body: []const u8) void {
    const writer = std.fs.File.stderr().writer();
    writer.print("Error: Notion API request failed with status {}\n", .{status_code}) catch {};

    // Provide helpful messages for common status codes
    switch (status_code) {
        401 => writer.print("  Unauthorized: Check your NOTION_API_TOKEN\n", .{}) catch {},
        403 => writer.print("  Forbidden: The integration may not have access to this page\n", .{}) catch {},
        404 => writer.print("  Not Found: The page or block does not exist\n", .{}) catch {},
        429 => writer.print("  Rate Limited: Too many requests, please try again later\n", .{}) catch {},
        500...599 => writer.print("  Server Error: Notion API is experiencing issues\n", .{}) catch {},
        else => {},
    }

    writer.print("Response: {s}\n", .{response_body}) catch {};
}

fn printUsage(program_name: []const u8) void {
    const writer = std.fs.File.stderr().writer();
    writer.print("Usage: {s} <page-id-or-url>\n\n", .{program_name}) catch {};
    writer.print("Environment Variables:\n", .{}) catch {};
    writer.print("  NOTION_API_TOKEN - Your Notion integration token (required)\n\n", .{}) catch {};
    writer.print("Examples:\n", .{}) catch {};
    writer.print("  {s} abc123def456\n", .{program_name}) catch {};
    writer.print("  {s} https://www.notion.so/My-Page-abc123def456\n", .{program_name}) catch {};
}

fn extractPageId(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    if (isNotionUrl(input)) {
        const clean_path = try cleanUrlPath(input);
        return try findPageIdInPath(allocator, clean_path);
    }
    return try allocator.dupe(u8, input);
}

fn formatPageId(allocator: std.mem.Allocator, page_id: []const u8) ![]const u8 {
    // Remove any existing hyphens and spaces
    var cleaned = std.ArrayList(u8).init(allocator);
    defer cleaned.deinit();

    for (page_id) |c| {
        if (c != '-' and c != ' ') {
            try cleaned.append(c);
        }
    }

    const clean_id = cleaned.items;
    if (clean_id.len != PAGE_ID_LENGTH) {
        return NotionError.InvalidPageId;
    }

    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return std.fmt.allocPrint(
        allocator,
        "{s}-{s}-{s}-{s}-{s}",
        .{
            clean_id[0..8],
            clean_id[8..12],
            clean_id[12..16],
            clean_id[16..20],
            clean_id[20..32],
        },
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const writer = std.fs.File.stdout().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    const page_input = args[1];

    // Get API token from environment
    const api_token = std.process.getEnvVarOwned(allocator, "NOTION_API_TOKEN") catch {
        writer.print("Error: NOTION_API_TOKEN environment variable is not set\n\n", .{}) catch {};
        printUsage(args[0]);
        return NotionError.MissingApiToken;
    };
    defer allocator.free(api_token);

    // Extract and format page ID
    const page_id = try extractPageId(allocator, page_input);
    defer allocator.free(page_id);

    const formatted_id = try formatPageId(allocator, page_id);
    defer allocator.free(formatted_id);

    // Create HTTP client
    var client = http_client.HttpClient.init(allocator);
    defer client.deinit();

    // Fetch page blocks
    const url = try notion_config.buildBlockUrl(allocator, formatted_id);
    defer allocator.free(url);

    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_token});
    defer allocator.free(auth_header);

    const extra_headers = [_]std.http.Header{
        .{ .name = "Notion-Version", .value = notion_config.api_version },
    };

    var response = try client.getWithHeaders(url, auth_header, &extra_headers);
    defer response.deinit();

    if (response.status_code != 200) {
        printApiError(response.status_code, response.body);
        return NotionError.ApiRequestFailed;
    }

    const response_body = try allocator.dupe(u8, response.body);
    defer allocator.free(response_body);

    if (response_body.len == 0) {
        writer.print("Error: Empty response from API\n", .{}) catch {};
        return NotionError.InvalidResponse;
    }

    // Parse JSON response
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        response_body,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value;
    if (root.object.get("results")) |results| {
        if (results == .array) {
            for (results.array.items) |block| {
                try block_formatter.printBlockContent(&client, allocator, api_token, notion_config, block, 0);
            }
        }
    } else {
        writer.print("No content found or invalid response format\n", .{}) catch {};
    }
}
