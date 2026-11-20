# spm-mcp — MCP server for Secure Proxy Manager.
# Small image; runs the stdio MCP server. Point it at the SPM backend via env.
# Pinned by digest like every other base image in this repository. It was the
# one Dockerfile addressed by a bare tag, so a rebuild silently adopted a new
# Debian base (SECURE-DEP-02).
#
# Every Python package comes from a lock with hashes: requirements.txt for the
# runtime, requirements-build.txt for the build backend. "pip install ." used
# to resolve whatever versions PyPI served at build time, with no hash check.
# Regenerate a lock with the command in its header.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

WORKDIR /src
COPY requirements-build.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.txt
COPY pyproject.toml README.md ./
COPY spm_mcp ./spm_mcp
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation -w /wheels .

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-deps /wheels/*.whl && rm -rf /wheels

# Non-root.
RUN useradd -u 1000 -m mcp
USER mcp

# stdio transport (MCP clients spawn and speak over stdio).
ENTRYPOINT ["spm-mcp"]
