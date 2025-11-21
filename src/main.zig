const std = @import("std");
const http_client = @import("http_client.zig");

const NOTION_API_BASE = "https://api.notion.com/v1";
const NOTION_VERSION = "2022-06-28";

const PAGE_ID_LENGTH = 32;
const MAX_INDENT = 80;
const INDENT_INCREMENT = 2;

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

fn printUsage(program_name: []const u8) void {
    const writer = std.fs.File.stderr().deprecatedWriter();
    writer.print("Usage: {s} <page-id-or-url>\n\n", .{program_name}) catch {};
    writer.print("Environment Variables:\n", .{}) catch {};
    writer.print("  NOTION_API_TOKEN - Your Notion integration token (required)\n\n", .{}) catch {};
    writer.print("Examples:\n", .{}) catch {};
    writer.print("  {s} abc123def456\n", .{program_name}) catch {};
    writer.print("  {s} https://www.notion.so/My-Page-abc123def456\n", .{program_name}) catch {};
}

fn extractPageId(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    // If input looks like a URL, extract the ID from it
    if (std.mem.indexOf(u8, input, "notion.so/") != null) {
        // Find the content after "notion.so/"
        const notion_prefix = "notion.so/";
        if (std.mem.indexOf(u8, input, notion_prefix)) |prefix_idx| {
            const after_prefix = input[prefix_idx + notion_prefix.len ..];
            // Remove query parameters if present
            var query_iter = std.mem.splitScalar(u8, after_prefix, '?');
            if (query_iter.next()) |id_part| {
                // Remove trailing slash if present
                var end = id_part.len;
                while (end > 0 and id_part[end - 1] == '/') {
                    end -= 1;
                }
                const clean_id = id_part[0..end];

                // The format could be:
                // 1. "workspace-name/2a9f69455b3080c88458f7ff164a5455" (with slash and workspace)
                // 2. "workspace-name-2a9f69455b3080c88458f7ff164a5455" (with hyphens)
                // 3. "2a9f69455b3080c88458f7ff164a5455" (just ID)

                // First, try splitting by slash (workspace/id format)
                if (std.mem.indexOf(u8, clean_id, "/")) |slash_idx| {
                    const potential_id = clean_id[slash_idx + 1 ..];
                    if (potential_id.len == PAGE_ID_LENGTH) {
                        return try allocator.dupe(u8, potential_id);
                    }
                }

                // Otherwise, look for the last segment that looks like a 32-char hex ID
                var segments = std.mem.splitBackwardsScalar(u8, clean_id, '-');
                while (segments.next()) |segment| {
                    // Check if this could be a 32-char hex string (page ID)
                    if (segment.len == PAGE_ID_LENGTH and isHexString(segment)) {
                        return try allocator.dupe(u8, segment);
                    }
                }

                // If no 32-char segment found, return the whole thing
                return try allocator.dupe(u8, clean_id);
            }
        }
        return NotionError.InvalidPageId;
    }

    // Otherwise, assume it's already a page ID
    return try allocator.dupe(u8, input);
}

fn formatPageId(allocator: std.mem.Allocator, page_id: []const u8) ![]const u8 {
    // Remove any existing hyphens
    var cleaned: std.ArrayList(u8) = .{};
    defer cleaned.deinit(allocator);

    for (page_id) |c| {
        if (c != '-' and c != ' ') {
            try cleaned.append(allocator, c);
        }
    }

    // Format as UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    const clean_id = cleaned.items;
    if (clean_id.len != PAGE_ID_LENGTH) {
        return NotionError.InvalidPageId;
    }

    var formatted: std.ArrayList(u8) = .{};
    defer formatted.deinit(allocator);

    try formatted.appendSlice(allocator, clean_id[0..8]);
    try formatted.append(allocator, '-');
    try formatted.appendSlice(allocator, clean_id[8..12]);
    try formatted.append(allocator, '-');
    try formatted.appendSlice(allocator, clean_id[12..16]);
    try formatted.append(allocator, '-');
    try formatted.appendSlice(allocator, clean_id[16..20]);
    try formatted.append(allocator, '-');
    try formatted.appendSlice(allocator, clean_id[20..32]);

    return formatted.toOwnedSlice(allocator);
}

fn fetchChildren(
    client: *http_client.HttpClient,
    allocator: std.mem.Allocator,
    api_token: []const u8,
    block_id: []const u8,
) ![]const u8 {
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/blocks/{s}/children",
        .{ NOTION_API_BASE, block_id },
    );
    defer allocator.free(url);

    // Prepare authorization header
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_token});
    defer allocator.free(auth_header);

    // Prepare extra headers for Notion API
    const extra_headers = [_]std.http.Header{
        .{ .name = "Notion-Version", .value = NOTION_VERSION },
    };

    // Make the GET request with custom headers
    var response = try client.getWithHeaders(url, auth_header, &extra_headers);
    defer response.deinit();

    if (response.status_code != 200) {
        const writer = std.fs.File.stderr().deprecatedWriter();
        writer.print("Error: API returned status {}\n", .{response.status_code}) catch {};
        writer.print("Response body: {s}\n", .{response.body}) catch {};
        return NotionError.ApiRequestFailed;
    }

    // Duplicate the body since response.deinit will free it
    return try allocator.dupe(u8, response.body);
}

fn printBlockContent(
    client: *http_client.HttpClient,
    allocator: std.mem.Allocator,
    api_token: []const u8,
    block: std.json.Value,
    indent: usize,
) !void {
    const writer = std.fs.File.stdout().deprecatedWriter();
    const indent_str = " " ** MAX_INDENT;

    // Print indentation
    if (indent < MAX_INDENT) {
        writer.print("{s}", .{indent_str[0..indent]}) catch {};
    }

    const block_obj = block.object;
    const block_type = block_obj.get("type") orelse return;

    if (block_type != .string) return;
    const type_str = block_type.string;

    // Handle different block types
    if (std.mem.eql(u8, type_str, "paragraph")) {
        if (block_obj.get("paragraph")) |para| {
            if (para.object.get("rich_text")) |rich_text| {
                if (rich_text == .array) {
                    for (rich_text.array.items) |text_item| {
                        if (text_item.object.get("plain_text")) |plain_text| {
                            if (plain_text == .string) {
                                writer.print("{s}", .{plain_text.string}) catch {};
                            }
                        }
                    }
                }
            }
        }
    } else if (std.mem.eql(u8, type_str, "heading_1")) {
        writer.print("# ", .{}) catch {};
        if (block_obj.get("heading_1")) |heading| {
            printRichText(heading.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "heading_2")) {
        writer.print("## ", .{}) catch {};
        if (block_obj.get("heading_2")) |heading| {
            printRichText(heading.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "heading_3")) {
        writer.print("### ", .{}) catch {};
        if (block_obj.get("heading_3")) |heading| {
            printRichText(heading.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "bulleted_list_item")) {
        writer.print("- ", .{}) catch {};
        if (block_obj.get("bulleted_list_item")) |item| {
            printRichText(item.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "numbered_list_item")) {
        writer.print("1. ", .{}) catch {};
        if (block_obj.get("numbered_list_item")) |item| {
            printRichText(item.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "code")) {
        if (block_obj.get("code")) |code| {
            writer.print("```\n", .{}) catch {};
            printRichText(code.object.get("rich_text"));
            writer.print("\n```", .{}) catch {};
        }
    } else if (std.mem.eql(u8, type_str, "quote")) {
        writer.print("> ", .{}) catch {};
        if (block_obj.get("quote")) |quote| {
            printRichText(quote.object.get("rich_text"));
        }
    } else if (std.mem.eql(u8, type_str, "divider")) {
        writer.print("--------------------", .{}) catch {};
    } else if (std.mem.eql(u8, type_str, "bookmark")) {
        if (block_obj.get("bookmark")) |bookmark| {
             if (bookmark.object.get("url")) |url| {
                 if (url == .string) {
                     writer.print("[Bookmark: {s}]", .{url.string}) catch {};
                 }
             }
        }
    } else {
        writer.print("[{s}]", .{type_str}) catch {};
    }
    writer.print("\n", .{}) catch {};

    // Check for children
    if (block_obj.get("has_children")) |has_children| {
        if (has_children == .bool and has_children.bool) {
            if (block_obj.get("id")) |id_val| {
                if (id_val == .string) {
                    const block_id = id_val.string;
                    const response = try fetchChildren(client, allocator, api_token, block_id);
                    defer allocator.free(response);

                    const parsed = try std.json.parseFromSlice(
                        std.json.Value,
                        allocator,
                        response,
                        .{},
                    );
                    defer parsed.deinit();

                    const root = parsed.value;
                    if (root.object.get("results")) |results| {
                        if (results == .array) {
                            for (results.array.items) |child| {
                                try printBlockContent(client, allocator, api_token, child, indent + INDENT_INCREMENT);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn printRichText(rich_text_opt: ?std.json.Value) void {
    const writer = std.fs.File.stdout().deprecatedWriter();
    const rich_text = rich_text_opt orelse return;
    if (rich_text != .array) return;

    for (rich_text.array.items) |text_item| {
        if (text_item.object.get("plain_text")) |plain_text| {
            if (plain_text == .string) {
                writer.print("{s}", .{plain_text.string}) catch {};
            }
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const writer = std.fs.File.stdout().deprecatedWriter();

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
    const response = try fetchChildren(&client, allocator, api_token, formatted_id);
    defer allocator.free(response);

    if (response.len == 0) {
        writer.print("Error: Empty response from API\n", .{}) catch {};
        return NotionError.InvalidResponse;
    }

    // Parse JSON response
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        response,
        .{},
    );
    defer parsed.deinit();

    const root = parsed.value;
    if (root.object.get("results")) |results| {
        if (results == .array) {
            for (results.array.items) |block| {
                try printBlockContent(&client, allocator, api_token, block, 0);
            }
        }
    } else {
        writer.print("No content found or invalid response format\n", .{}) catch {};
    }
}
