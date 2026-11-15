#!/usr/bin/env bash
# Build the spm command for every platform a release ships, inside the same
# pinned golang image the backend image is built with, and write SHA256SUMS.
#
# Usage: scripts/build-cli-assets.sh VERSION OUTDIR [GIT_SHA]
#   VERSION  the release (v3.39.0) or "dry-run"; it names the files
#   OUTDIR   where the binaries and SHA256SUMS go (created, must be empty)
#
# The binaries are static (CGO_ENABLED=0) and built with -trimpath, as the
# backend is, with the commit injected so `spm version` names its tree.
set -euo pipefail
version="${1:?usage: build-cli-assets.sh VERSION OUTDIR [GIT_SHA]}"
out="${2:?usage: build-cli-assets.sh VERSION OUTDIR [GIT_SHA]}"
sha="${3:-unknown}"
root="$(cd "$(dirname "$0")/.." && pwd)"

img=$(sed -n 's/^FROM \(golang:[^ ]*\) AS builder$/\1/p' "$root/backend-go/Dockerfile")
[ -n "$img" ] || { echo "no pinned golang builder in backend-go/Dockerfile" >&2; exit 1; }
mkdir -p "$out"
[ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 1; }
out="$(cd "$out" && pwd)"

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"
docker run --rm -v "$root/backend-go:/src:ro" -v "$out:/out" \
  -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -e CGO_ENABLED=0 \
  -e VERSION="$version" -e GIT_SHA="$sha" -e TARGETS="$targets" \
  -w /src "$img" sh -euc '
    for t in $TARGETS; do
      os=${t%/*}; arch=${t#*/}
      name="spm_${VERSION}_${os}_${arch}"
      [ "$os" = windows ] && name="$name.exe"
      GOOS=$os GOARCH=$arch go build -trimpath \
        -ldflags="-s -w -X github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config.GitCommit=${GIT_SHA}" \
        -o "/out/$name" ./cmd/spm
      echo "built $name"
    done'

(cd "$out" && sha256sum spm_* > SHA256SUMS 2>/dev/null || shasum -a 256 spm_* > SHA256SUMS)
n=$(wc -l < "$out/SHA256SUMS" | tr -d ' ')
[ "$n" -eq 5 ] || { echo "SHA256SUMS lists $n files, want 5" >&2; exit 1; }
cat "$out/SHA256SUMS"
