# spm-mcp — MCP server for Secure Proxy Manager.
# Small image; runs the stdio MCP server. Point it at the SPM backend via env.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY spm_mcp ./spm_mcp

RUN pip install --no-cache-dir .

# Non-root.
RUN useradd -u 1000 -m mcp
USER mcp

# stdio transport (MCP clients spawn and speak over stdio).
ENTRYPOINT ["spm-mcp"]
