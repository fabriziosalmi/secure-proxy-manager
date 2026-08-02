FROM alpine:3.21

# bash (arrays/[[ ]]), curl (proxy client), jq (corpus + report JSON).
RUN apk add --no-cache bash curl jq coreutils

WORKDIR /adversarial

# Build context is tests/adversarial/ (see docker-compose.adversarial.yml) so the
# corpus is reachable. Baked-in defaults; run.sh bind-mounts the live versions
# over these for fast iteration (edit corpus/driver, re-run, no rebuild).
COPY attacker/attack.sh /adversarial/attack.sh
COPY attacker/api-attack.sh /adversarial/api-attack.sh
COPY corpus.json /adversarial/corpus.json
COPY api-corpus.json /adversarial/api-corpus.json
RUN chmod +x /adversarial/attack.sh /adversarial/api-attack.sh

# Default entrypoint runs plane 1 (block-matrix); run.sh also invokes the API
# plane via `run --rm --entrypoint /adversarial/api-attack.sh`.
ENTRYPOINT ["/adversarial/attack.sh"]
