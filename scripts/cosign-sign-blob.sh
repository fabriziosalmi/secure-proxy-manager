#!/usr/bin/env bash
# Keyless-sign a file (the SHA256SUMS of the spm binaries) into a sigstore
# bundle, and prove the bundle verifies against the release workflow identity
# SECURITY.md documents, as scripts/cosign-sign.sh does for the images.
#
# Usage: scripts/cosign-sign-blob.sh FILE
# Writes FILE.sigstore.json next to FILE.
#
# Each attempt is a new cosign process with a new ephemeral key, so a retry
# after a lost answer cannot collide with the entry the first attempt made in
# the transparency log (the Rekor 409 that cost v3.18.1 a signature).
set -uo pipefail
file="${1:?usage: cosign-sign-blob.sh FILE}"
bundle="$file.sigstore.json"
attempts="${COSIGN_ATTEMPTS:-3}"
delay="${COSIGN_RETRY_DELAY:-15}"
identity='^https://github\.com/fabriziosalmi/secure-proxy-manager/\.github/workflows/multi-arch\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
issuer=https://token.actions.githubusercontent.com

for i in $(seq 1 "$attempts"); do
    rm -f "$bundle"
    if cosign sign-blob --yes --bundle "$bundle" "$file"; then
        break
    fi
    if [ "$i" -eq "$attempts" ]; then
        echo "::error::cosign sign-blob failed $attempts times for $file"
        exit 1
    fi
    echo "::warning::cosign sign-blob attempt $i of $attempts failed for $file; retrying in ${delay}s"
    sleep "$delay"
done

if ! cosign verify-blob --bundle "$bundle" \
    --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" "$file"; then
    echo "::error::the bundle written for $file does not verify against the release workflow identity"
    exit 1
fi
echo "signed and verified $file ($bundle)"
