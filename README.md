# Notion CLI (Zig)

A command-line tool written in Zig to retrieve and display Notion page content using the Notion API.

## Features

- Fetch Notion page content by URL or page ID
- Display formatted content (headings, paragraphs, lists, code blocks, quotes)
- Simple command-line interface

## Prerequisites

- [Zig](https://ziglang.org/download/) (0.13.0 or later, tested with 0.16.0-dev)
- A Notion integration token ([Create one here](https://www.notion.so/my-integrations))

## Setup

### 1. Create a Notion Integration

1. Go to [https://www.notion.so/my-integrations](https://www.notion.so/my-integrations)
2. Click "+ New integration"
3. Give it a name (e.g., "CLI Reader")
4. Select the workspace you want to access
5. Click "Submit"
6. Copy the "Internal Integration Token"

### 2. Share Pages with Your Integration

For each page you want to access:
1. Open the page in Notion
2. Click the "..." menu in the top right
3. Scroll down and click "Add connections"
4. Search for and select your integration

### 3. Set Environment Variable

Export your integration token as an environment variable:

```bash
export NOTION_API_TOKEN="your_integration_token_here"
```

To make this permanent, add it to your `~/.bashrc`, `~/.zshrc`, or equivalent shell configuration file.

## Building

```bash
zig build
```

The executable will be created at `zig-out/bin/notion-cli`.

## Usage

### Using a Page ID

```bash
./zig-out/bin/notion-cli abc123def456
```

### Using a Notion URL

```bash
./zig-out/bin/notion-cli "https://www.notion.so/My-Page-abc123def456"
```

### Run Directly

```bash
zig build run -- <page-id-or-url>
```

## How It Works

1. **Parses Input**: Accepts either a raw page ID or a full Notion URL
2. **Extracts Page ID**: If a URL is provided, extracts the page ID from it
3. **Authenticates**: Uses the `NOTION_API_TOKEN` environment variable
4. **Fetches Content**: Calls the Notion API to retrieve page blocks
5. **Displays Content**: Formats and prints the content to the terminal

## Supported Block Types

- Headings (H1, H2, H3)
- Paragraphs
- Bulleted lists
- Numbered lists
- Code blocks
- Quotes
- Other block types (shown with type label)

## API Reference

This tool uses the following Notion API endpoints:
- `GET /v1/blocks/{block_id}/children` - Retrieve block children (page content)

Documentation: [https://developers.notion.com/reference/intro](https://developers.notion.com/reference/intro)

## Troubleshooting

### "NOTION_API_TOKEN environment variable is not set"

Make sure you've exported the environment variable:
```bash
export NOTION_API_TOKEN="your_token_here"
```

### "API returned status 401"

Your integration token might be invalid or expired. Create a new integration token from your Notion integrations page.

### "API returned status 403"

The page hasn't been shared with your integration. Follow the "Share Pages with Your Integration" steps above.

### "API returned status 404"

The page ID is invalid or the page doesn't exist. Double-check the page ID or URL.

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
