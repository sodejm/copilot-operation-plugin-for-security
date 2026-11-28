"""Local stdio only. The SDK owns protocol/session handling, not COPS authority."""

from __future__ import annotations

import os
import sys
from functools import partial
from threading import Event

from cops.operations.catalog import declarations, tool_name
from cops.operations.contracts import MAX_BYTES, OperationError, decode, encode, response
from cops.operations.service import OperationService


class BoundedInput:
    async def __aiter__(self):
        import anyio

        while True:
            raw = await anyio.to_thread.run_sync(partial(sys.stdin.buffer.readline, MAX_BYTES + 1))
            if not raw:
                return
            # Reject duplicate keys, non-finite numbers, invalid UTF-8 and deep trees
            # before the SDK receives a frame. Never include raw bytes in exceptions.
            document = decode(raw)
            # SDK validation exceptions may contain rejected private values.
            from mcp.types import JSONRPCMessage

            try:
                JSONRPCMessage.model_validate(document)
            except Exception as exc:
                raise OperationError("invalid_protocol") from exc
            yield raw.decode("utf-8")


class BoundedOutput:
    async def write(self, text):
        import anyio

        raw = text.encode("utf-8")
        if len(raw) > MAX_BYTES + 65536:
            raise OperationError("output_size_limit")
        await anyio.to_thread.run_sync(sys.stdout.buffer.write, raw)

    async def flush(self):
        import anyio

        await anyio.to_thread.run_sync(sys.stdout.buffer.flush)


def create_server(service=None):
    import anyio
    from mcp import types
    from mcp.server.lowlevel import Server

    service = service or OperationService(runtime_config=os.environ.get("COPS_RUNTIME_CONFIG"))
    server = Server("cops", version="0.1.0")
    operations = {tool_name(item["operation_id"]): item for item in declarations()}

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(
                name=name,
                description=item["description"],
                inputSchema=item["input_schema"],
                outputSchema=item["output_schema"],
                annotations=types.ToolAnnotations(
                    readOnlyHint=not item["effects"]["durable_writes"],
                    destructiveHint=item["effects"]["executes_samples"],
                    idempotentHint=not (item["effects"]["network"] or item["effects"]["durable_writes"]),
                    openWorldHint=item["effects"]["network"],
                ),
            )
            for name, item in operations.items()
        ]

    # Validate in our shared service: SDK validation errors can echo private input.
    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        operation = operations.get(name)
        if operation is None:
            result = response(status="blocked", code="unknown_operation")
        else:
            cancelled = Event()
            try:
                with anyio.fail_after(30):
                    result = await anyio.to_thread.run_sync(
                        partial(
                            service.invoke,
                            {
                                "schema_version": "cops.operation-request/v1",
                                "operation_id": operation["operation_id"],
                                "arguments": arguments,
                            },
                            cancelled=cancelled,
                        ),
                        abandon_on_cancel=True,
                    )
            except TimeoutError:
                result = response(
                    operation["operation_id"],
                    status="blocked",
                    code="duration_limit",
                    next_action="Inspect persisted run status before retrying the local operation.",
                )
            finally:
                cancelled.set()
        # Do not duplicate evidence in text and structuredContent.
        encode(result)
        return types.CallToolResult(
            structuredContent=result,
            content=[types.TextContent(type="text", text="COPS operation: " + result["status"])],
            isError=result["status"] in {"failed", "blocked"},
        )

    return server


async def serve():
    from mcp.server.stdio import stdio_server

    server = create_server()
    async with stdio_server(stdin=BoundedInput(), stdout=BoundedOutput()) as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main():
    try:
        import anyio
        import mcp  # noqa: F401
    except ImportError:
        sys.stderr.write("COPS MCP requires the optional mcp==1.30.0 dependency.\n")
        return 2
    # SDK warnings can repeat client-selected tool/method names. This executable
    # exposes only our fixed, content-free transport diagnostic on stderr.
    import logging

    logging.disable(logging.CRITICAL)
    try:
        anyio.run(serve)
    except KeyboardInterrupt:
        return 130
    except Exception:
        # Transport failures must not serialize SDK exception payloads or tracebacks.
        sys.stderr.write("COPS MCP transport failed; no execution authority was granted.\n")
        return 2
    return 0
