const std = @import("std");
const http_client = @import("http_client.zig");

const MAX_INDENT = 80;
const INDENT_INCREMENT = 2;

pub const BlockType = enum {
    paragraph,
    heading_1,
    heading_2,
    heading_3,
    bulleted_list_item,
    numbered_list_item,
    code,
    quote,
    divider,
    bookmark,
    unsupported,

    pub fn fromString(s: []const u8) BlockType {
        return std.meta.stringToEnum(BlockType, s) orelse .unsupported;
    }
};

fn handleRichTextBlock(writer: anytype, block_obj: std.json.ObjectMap, block_type_str: []const u8, prefix: []const u8) void {
    writer.print("{s}", .{prefix}) catch {};
    if (block_obj.get(block_type_str)) |block_data| {
        printRichText(block_data.object.get("rich_text"));
    }
}

fn handleCodeBlock(writer: anytype, block_obj: std.json.ObjectMap) void {
    if (block_obj.get("code")) |code| {
        writer.print("```\n", .{}) catch {};
        printRichText(code.object.get("rich_text"));
        writer.print("\n```", .{}) catch {};
    }
}

fn handleBookmarkBlock(writer: anytype, block_obj: std.json.ObjectMap) void {
    if (block_obj.get("bookmark")) |bookmark| {
        if (bookmark.object.get("url")) |url| {
            if (url == .string) {
                writer.print("[Bookmark: {s}]", .{url.string}) catch {};
            }
        }
    }
}

fn printRichText(rich_text_opt: ?std.json.Value) void {
    const writer = std.io.getStdOut().writer();
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

pub fn printBlockContent(
    client: *http_client.HttpClient,
    allocator: std.mem.Allocator,
    api_token: []const u8,
    notion_config: anytype,
    block: std.json.Value,
    indent: usize,
) !void {
    const writer = std.io.getStdOut().writer();
    const indent_str = " " ** MAX_INDENT;

    // Print indentation
    if (indent < MAX_INDENT) {
        writer.print("{s}", .{indent_str[0..indent]}) catch {};
    }

    const block_obj = block.object;
    const block_type_val = block_obj.get("type") orelse return;

    if (block_type_val != .string) return;
    const type_str = block_type_val.string;
    const block_type = BlockType.fromString(type_str);

    // Handle different block types
    switch (block_type) {
        .paragraph => handleRichTextBlock(writer, block_obj, "paragraph", ""),
        .heading_1 => handleRichTextBlock(writer, block_obj, "heading_1", "# "),
        .heading_2 => handleRichTextBlock(writer, block_obj, "heading_2", "## "),
        .heading_3 => handleRichTextBlock(writer, block_obj, "heading_3", "### "),
        .bulleted_list_item => handleRichTextBlock(writer, block_obj, "bulleted_list_item", "- "),
        .numbered_list_item => handleRichTextBlock(writer, block_obj, "numbered_list_item", "1. "),
        .quote => handleRichTextBlock(writer, block_obj, "quote", "> "),
        .code => handleCodeBlock(writer, block_obj),
        .divider => writer.print("--------------------", .{}) catch {},
        .bookmark => handleBookmarkBlock(writer, block_obj),
        .unsupported => writer.print("[{s}]", .{type_str}) catch {},
    }
    writer.print("\n", .{}) catch {};

    // Check for children
    if (block_obj.get("has_children")) |has_children| {
        if (has_children == .bool and has_children.bool) {
            if (block_obj.get("id")) |id_val| {
                if (id_val == .string) {
                    const block_id = id_val.string;
                    const response = try fetchChildren(client, allocator, api_token, notion_config, block_id);
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
                                try printBlockContent(client, allocator, api_token, notion_config, child, indent + INDENT_INCREMENT);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn fetchChildren(
    client: *http_client.HttpClient,
    allocator: std.mem.Allocator,
    api_token: []const u8,
    notion_config: anytype,
    block_id: []const u8,
) ![]const u8 {
    const url = try notion_config.buildBlockUrl(allocator, block_id);
    defer allocator.free(url);

    // Prepare authorization header
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{api_token});
    defer allocator.free(auth_header);

    // Prepare extra headers for Notion API
    const extra_headers = [_]std.http.Header{
        .{ .name = "Notion-Version", .value = notion_config.api_version },
    };

    // Make the GET request with custom headers
    var response = try client.getWithHeaders(url, auth_header, &extra_headers);
    defer response.deinit();

    if (response.status_code != 200) {
        const writer = std.io.getStdErr().writer();
        writer.print("Error: Notion API request failed with status {}\n", .{response.status_code}) catch {};

        // Provide helpful messages for common status codes
        switch (response.status_code) {
            401 => writer.print("  Unauthorized: Check your NOTION_API_TOKEN\n", .{}) catch {},
            403 => writer.print("  Forbidden: The integration may not have access to this page\n", .{}) catch {},
            404 => writer.print("  Not Found: The page or block does not exist\n", .{}) catch {},
            429 => writer.print("  Rate Limited: Too many requests, please try again later\n", .{}) catch {},
            500...599 => writer.print("  Server Error: Notion API is experiencing issues\n", .{}) catch {},
            else => {},
        }

        writer.print("Response: {s}\n", .{response.body}) catch {};
        return error.ApiRequestFailed;
    }

    // Duplicate the body since response.deinit will free it
    return try allocator.dupe(u8, response.body);
}
