# WAF Intelligence Roadmap — LLM-Augmented Security Gateway

> Vision: Transform from static proxy → radar (ML/stats, done) → autonomous security officer (LLM + MCP)

## Current State (v2.2.x)

```
Layer 1: Regex Engine      — 166 rules, 21 categories, dual-scan (raw + normalized)
Layer 2: Behavioral Stats  — Shannon entropy, beaconing, dest sharding, protocol ghosting
Layer 3: ML-Lite           — DGA detection (bigram), typosquatting (Levenshtein), safe URL cache
```

All three layers run in **<1ms per request** in Go. Zero external dependencies.

## The LLM Question: Honest Assessment

### What Gemini proposes
A local LLM (Qwen 2.5 3B / Phi-3 / Llama 3 8B) integrated via MCP, acting as an "autonomous SOC analyst" that reads logs, explains blocks, generates rules, and detects threats in natural language.

### What's genuinely valuable
1. **Natural language troubleshooting** — "Why can't my staging server update?" → LLM queries logs, finds the block, explains it
2. **Rule generation** — "Block all Chinese IPs except Alibaba Cloud" → LLM writes the ACL
3. **Log summarization** — Daily 5-line security briefing instead of reading 10K log entries
4. **Security education** — Block page explains WHY in human language, not just "403 DENIED"

### What's NOT worth it (for our stack)
1. **Real-time inference in the request path** — Even quantized, 3B model = 50-100ms latency PER REQUEST. Our entire WAF pipeline is <1ms. Adding LLM in-line would 100x the latency.
2. **Fine-tuning** — Requires GPU training, dataset curation, evaluation pipeline. Our users don't have this infrastructure.
3. **Ollama as sidecar** — Adds 2-4GB RAM for the model alone. Our entire stack runs in 100MB. This is a 40x memory increase for "nice to have" features.
4. **MCP Tools with write access** — Letting an LLM `block_ip()` or `restart_squid()` autonomously is terrifying. One hallucination = network outage.

## The Right Architecture (if we do it)

### Principle: LLM is ADVISORY, never EXECUTIVE

The LLM can **suggest**, **explain**, and **summarize**. It cannot **block**, **modify**, or **restart** anything without human confirmation.

```
┌─────────────────────────────────────────────┐
│  Request Flow (FAST PATH — no LLM)          │
│  Client → Squid → ICAP/WAF (Go) → Internet │
│  Latency: P50 = 107ms                       │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Analysis Flow (SLOW PATH — optional LLM)   │
│  WAF JSONL logs → Batch analyzer (cron) →   │
│  LLM summarizes → Dashboard widget          │
│  Latency: doesn't matter (async)            │
└─────────────────────────────────────────────┘
```

### Key decisions:
- **LLM never touches the request path** — only reads logs after the fact
- **LLM is optional** — product works 100% without it
- **LLM runs async** — cron job, not real-time
- **All actions require human approval** — LLM suggests "block this IP?", admin clicks confirm

## Implementation Tiers

### Tier 0: No LLM (current — already excellent)
- WAF explainability via category + rule ID + score
- Dashboard analytics, Threat Intel, Shadow IT
- Estimated coverage: 95% of what a human SOC analyst would catch

### Tier 1: Smart Summaries (no LLM needed)
**Effort: 4-6h | RAM: 0 extra**

Use Go templates + statistics to generate human-readable summaries:
```
"Last 24h: 3,412 requests inspected, 186 blocked (5.4%).
Top threat: SQL Injection (170 blocks from 192.168.100.7).
New domain detected: suspicious-cdn.xyz (first seen today, high entropy).
Recommendation: Review 192.168.100.7 — unusually high block rate."
```

This is NOT an LLM — it's structured template generation from the data we already have. Covers 80% of the "daily briefing" use case with zero additional resources.

### Tier 2: Local LLM (compiled into Go backend)
**Effort: 8-12h | RAM: +1-2GB**

For users who want natural language interaction:
- **llama.cpp via Go bindings** (`go-llama.cpp`) — compiles directly into the backend binary
- No wrapper (Ollama is bloated and trending closed-source — rejected)
- No Python (vLLM/MLX are overkill or non-portable)
- No sidecar container — the LLM runs IN the Go backend process
- Model: `qwen2.5-coder-1.5b.Q4_K_M.gguf` (~1GB file, ~1.5GB RAM)
- Model file mounted as Docker volume: `-v ./models:/models`
- MCP server in Go exposing read-only tools:
  - `get_recent_blocks(hours=24)` → returns JSON
  - `explain_rule(rule_id)` → returns rule description
  - `analyze_ip(ip)` → returns traffic profile
  - `suggest_whitelist(domain)` → checks if domain is safe
- Chat widget in Dashboard
- Build flag: `go build -tags llm` enables LLM support (without flag = zero overhead)

**Runtime selection (auto-detected):**
- Apple Silicon (M1+): MLX backend via cgo (fastest on Mac)
- CUDA GPU: llama.cpp CUDA backend
- CPU only: llama.cpp AVX2/NEON (works everywhere, slower)

**Critical constraints:**
- NO write tools (no block_ip, no restart_squid)
- NO real-time inference (batch only, async goroutine)
- NO auto-actions (always human-in-the-loop)
- Only activates if model file exists in `/models/` directory
- Without model file = zero RAM overhead, zero latency impact

### Tier 3: RAG over documentation + logs
**Effort: 16-20h | RAM: +4GB**

- Vector embeddings of Squid docs, WAF rules, project README
- User asks "How do I block TikTok?" → RAG finds the right approach
- Semantic search over historical logs ("Show me all suspicious traffic last week")
- This is where MCP shines — the model has structured access to all system state

## What We Should Actually Do

### Now (v2.3): Tier 1 — Smart Summaries
- Go template-based daily briefing on Dashboard
- "Security Digest" card: 5-line summary of last 24h
- Zero extra RAM, zero extra containers
- Covers 80% of the LLM value proposition

### Later (v3.0): Tier 2 — Embedded LLM via llama.cpp
- Only after the product is stable and adopted
- Compiled into Go backend with build tag: `go build -tags llm`
- User drops a GGUF model file in `./models/` → LLM activates
- No Ollama, no Python, no sidecar — one binary, one process
- Read-only MCP tools, advisory only
- Chat widget in Dashboard

### Probably Never: Tier 3 — Full RAG
- Too complex for self-hosted
- Requires embedding model + vector DB + retrieval pipeline
- Hosted SaaS product territory, not Docker compose

## The Uncomfortable Truth

A well-configured regex WAF with behavioral heuristics catches **more threats per CPU cycle** than any LLM. Our 166 rules + entropy + DGA + typosquatting run in <1ms and catch 100% of test vectors.

An LLM adds:
- ✅ Explainability (WHY was this blocked?)
- ✅ Accessibility (non-technical users can ask questions)
- ✅ Discovery (find patterns humans miss in log noise)

An LLM does NOT add:
- ❌ Better detection (regex is deterministic, LLM is probabilistic)
- ❌ Better performance (LLM is 1000x slower)
- ❌ Better reliability (LLM can hallucinate, regex can't)

**The winning strategy: keep the fast deterministic engine for blocking, add the slow probabilistic engine for analysis.** Two separate paths. Never mix them.
