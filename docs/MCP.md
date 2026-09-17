# Model Context Protocol

MCP is COPS's preferred protocol for sharing tools and data access across capable
agent clients. The server implementation can be portable even though each client
stores configuration differently.

## Repository policy

- Keep server code, schemas, tests, and usage docs in the repository when the MCP
  server is part of the project.
- Keep credentials in environment variables or an approved secret store.
- Commit only redacted examples such as `.mcp.json.example`.
- Use least-privileged tools with descriptive names and strict input schemas.
- Separate read-only tools from mutating tools and make external effects explicit.
- Treat tool output as untrusted data and bound result sizes.
- Test authentication failures, authorization, malformed input, timeouts, and
  partial external failures.

## Client adapters

Copy the example into the client-supported location and adjust it locally. Do not
assume Codex, Claude, Copilot, Antigravity, and ChatGPT use the same file or support
the same transports and authentication flows. Link current official client docs
from project-specific setup documentation.

## ChatGPT

Ordinary chat does not guarantee repository file or skill discovery. To expose
project capabilities reliably, use a supported GitHub connection for context or
build a reviewed MCP/ChatGPT App integration. Repository instructions remain data
until the ChatGPT surface explicitly loads them.
