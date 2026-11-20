#!/usr/bin/env bash
# Verify an image reference's keyless signature against the release workflow
# identity documented in SECURITY.md, as a user would.
#
# Usage: scripts/cosign-verify.sh REF   (REF = registry/repo:tag or @sha256:...)
#
# The release dry run runs it on the current release's :latest, on GHCR and on
# the Docker Hub mirror, so the cosign the release would sign with is
# installed and working, and Docker Hub is reachable with the release's
# credentials, before a tag depends on either.
set -uo pipefail
ref="${1:?usage: cosign-verify.sh REF}"
identity='^https://github\.com/fabriziosalmi/secure-proxy-manager/\.github/workflows/multi-arch\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
issuer=https://token.actions.githubusercontent.com

command -v cosign >/dev/null 2>&1 && cosign version >/dev/null 2>&1 \
  || { echo "::error::cosign is not installed or does not run"; exit 1; }
if cosign verify --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null; then
  echo "verified: $ref is signed by the release workflow"
else
  echo "::error::$ref has no valid signature from the release workflow"
  exit 1
fi
