"""The operations docs/public/openapi.json marks as reachable from the MCP
server (x-spm-surfaces contains "mcp", from backend-go/internal/handlers/
surfaces.go) are exactly the ones its tools call, and a tool is read-only
exactly when the operation it calls only reads.

Every tool is called against a stub of the API with a write token, so the
mutating ones are registered too; the requests the stub records are the
answer, not the source text.
"""

import asyncio
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("mcp")
pytest.importorskip("httpx")

from test_mcp_server import StubAPI, _load, _tools  # noqa: E402

SPEC = json.loads((Path(__file__).resolve().parents[2] / "docs/public/openapi.json").read_text())
OPS = [(m.upper(), p, op) for p, item in SPEC["paths"].items() for m, op in item.items()]
SAMPLE = {"string": "example.com", "integer": 1, "number": 1, "boolean": True, "array": [1], "object": {}}


def _operation(method, path):
    """The OpenAPI operation a request is, or None."""
    for m, p, op in OPS:
        pattern = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(p)) + "$"
        if m == method and re.match(pattern, path):
            return f"{m} {p}", op
    return None, None


def _called():
    """{tool: [operation keys]} and {operation key: operation} for every tool."""
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    try:
        api = StubAPI(scope="write")
        server = _load(mp, readonly="false", token="spm_x_y", api=api)
        tools = _tools(server)
        out, ops = {}, {}
        for name, tool in sorted(tools.items()):
            schema = tool.input_schema or {}
            args = {k: SAMPLE[v.get("type", "string")] for k, v in schema.get("properties", {}).items()
                    if k in schema.get("required", [])}
            before = len(api.calls)
            asyncio.run(server.mcp.call_tool(name, args))
            keys = []
            for req in api.calls[before:]:
                if req.url.path == "/api/session":
                    continue
                key, op = _operation(req.method, req.url.path)
                assert key, f"{name} calls {req.method} {req.url.path}, which the API does not have"
                keys.append(key)
                ops[key] = op
            out[name] = (tool, keys)
        return out, ops
    finally:
        mp.undo()


def test_every_tool_calls_one_operation_and_reads_only_when_it_only_reads():
    called, _ = _called()
    assert len(called) >= 13
    for name, (tool, keys) in called.items():
        assert len(keys) == 1, f"{name} calls {keys}"
        reads = keys[0].startswith("GET ")
        assert tool.annotations.read_only_hint is reads, f"{name} calls {keys[0]} and read_only_hint is {tool.annotations.read_only_hint}"


def test_the_tools_call_exactly_the_operations_marked_mcp():
    called, _ = _called()
    reached = {k for _, keys in called.values() for k in keys}
    marked = {f"{m} {p}" for m, p, op in OPS if "mcp" in op.get("x-spm-surfaces", [])}
    assert reached - marked == set(), "called by an MCP tool, not marked mcp in surfaces.go"
    assert marked - reached == set(), "marked mcp in surfaces.go, called by no MCP tool"
