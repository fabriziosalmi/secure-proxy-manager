#!/usr/bin/env bash
# Keyless-sign an image reference and prove the signature is attached.
#
# Usage: scripts/cosign-sign.sh REF   (REF = registry/repo@sha256:...)
#
# v3.18.1's Docker Hub signature failed with Rekor 409 "an equivalent entry
# already exists": the first upload was recorded at 14:28:51Z, its response
# was lost, cosign retried 35 s later and the duplicate was refused, so the
# signature never reached the registry and the job failed. A fresh cosign
# run signs with a new ephemeral key, so it cannot collide with the previous
# attempt: each attempt here is a new process, up to COSIGN_ATTEMPTS.
#
# Success is not cosign's exit code alone: the reference is then verified
# against the release workflow identity documented in SECURITY.md, so the
# step fails unless a valid signature is attached.
#
# The verify is retried: on v3.18.2 Docker Hub listed the signature (an OCI
# referrer created at 21:18:02Z) only after cosign verify had run at
# 21:18:04Z and found none, so a signed image failed the release. A
# signature that is still missing after VERIFY_ATTEMPTS checks fails it.
set -uo pipefail
ref="${1:?usage: cosign-sign.sh REF}"
attempts="${COSIGN_ATTEMPTS:-3}"
delay="${COSIGN_RETRY_DELAY:-15}"
verify_attempts="${VERIFY_ATTEMPTS:-6}"
verify_delay="${VERIFY_RETRY_DELAY:-10}"
identity='^https://github\.com/fabriziosalmi/secure-proxy-manager/\.github/workflows/multi-arch\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
issuer=https://token.actions.githubusercontent.com

for i in $(seq 1 "$attempts"); do
    if cosign sign --yes "$ref"; then
        break
    fi
    if [ "$i" -eq "$attempts" ]; then
        echo "::error::cosign sign failed $attempts times for $ref"
        exit 1
    fi
    echo "::warning::cosign sign attempt $i of $attempts failed for $ref; retrying in ${delay}s"
    sleep "$delay"
done

for i in $(seq 1 "$verify_attempts"); do
    if cosign verify --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null; then
        echo "signed and verified: $ref"
        exit 0
    fi
    [ "$i" -lt "$verify_attempts" ] && sleep "$verify_delay"
done
echo "::error::$ref has no valid signature from the release workflow after signing ($verify_attempts checks, ${verify_delay}s apart)"
exit 1
