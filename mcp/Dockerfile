# spm-mcp — MCP server for Secure Proxy Manager.
# Small image; runs the stdio MCP server. Point it at the SPM backend via env.
# Pinned by digest like every other base image in this repository. It was the
# one Dockerfile addressed by a bare tag, so a rebuild silently adopted a new
# Debian base (SECURE-DEP-02).
FROM python:3.12-slim@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79

WORKDIR /app
COPY pyproject.toml README.md ./
COPY spm_mcp ./spm_mcp

RUN pip install --no-cache-dir .

# Non-root.
RUN useradd -u 1000 -m mcp
USER mcp

# stdio transport (MCP clients spawn and speak over stdio).
ENTRYPOINT ["spm-mcp"]
