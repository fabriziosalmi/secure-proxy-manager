# WAF Intelligence Roadmap — From Regex to Deterministic ML

> Vision: Static proxy → radar (ML/stats, done) → **deterministic threat classifier** (ML ensembles, no LLM)
>
> Principle: **Every model must be faster than regex, or it doesn't ship.**

## Current State (v2.2.x)

```
Layer 1: Regex Engine      — 166 rules, 21 categories, dual-scan (raw + normalized)
Layer 2: Behavioral Stats  — Shannon entropy, beaconing, dest sharding, protocol ghosting
Layer 3: ML-Lite           — DGA detection (bigram), typosquatting (Levenshtein), safe URL cache
```

All three layers run in **<1ms per request** in Go. Zero external dependencies.
100% detection on test vectors, 0% false positives.

---

## Why NOT LLMs

| Property | Regex/ML Ensemble | LLM (even local) |
|----------|-------------------|-------------------|
| Latency | <1ms | 50-500ms |
| Deterministic | ✅ Same input → same output | ❌ Temperature, sampling, hallucination |
| RAM | 0 extra | +1-4GB |
| False positives | Controllable, tunable | Unpredictable |
| Explainability | Rule ID + score + category | "I think maybe..." |
| Offline | ✅ Always | ✅ But needs model file |
| Attack surface | Zero | Model injection, prompt injection |

**LLMs add stochasticity to a system that must be deterministic.** A WAF that blocks differently on Tuesday than Monday because the model sampled differently is not a WAF — it's a liability.

**LLMs add latency to a system that must be fast.** Our P50 is 107ms (network + Squid + ICAP). Adding 100ms of LLM inference doubles the user-perceived latency for zero security improvement.

**LLMs are susceptible to prompt injection** — the very attack class we're supposed to defend against.

---

## The Right Path: Deterministic ML Ensembles

### Architecture: Feature Vector → Ensemble → Score

```
                    ┌──────────────────────────────┐
 HTTP Request ──►   │  Feature Extractor (Go)       │
                    │  - URL length, depth, entropy  │
                    │  - Query param count/entropy   │
                    │  - Body size, MIME match       │
                    │  - Header count, order hash    │
                    │  - TLD risk score              │
                    │  - Domain age bucket           │
                    │  - Character class distribution │
                    │  Output: float32[32] vector    │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │  Ensemble Classifier           │
                    │  ┌─────────────────────────┐  │
                    │  │ Model 1: Random Forest   │──► score₁
                    │  │ (trained on SQLi/XSS)    │  │
                    │  └─────────────────────────┘  │
                    │  ┌─────────────────────────┐  │
                    │  │ Model 2: Gradient Boost  │──► score₂
                    │  │ (trained on C2/exfil)    │  │
                    │  └─────────────────────────┘  │
                    │  ┌─────────────────────────┐  │
                    │  │ Model 3: Isolation Forest│──► score₃
                    │  │ (anomaly detection)      │  │
                    │  └─────────────────────────┘  │
                    │                               │
                    │  Final = w₁·s₁ + w₂·s₂ + w₃·s₃ │
                    │  Threshold: block if > 0.85   │
                    └──────────┬───────────────────┘
                               │
                    ┌──────────▼───────────────────┐
                    │  Decision: ALLOW / BLOCK      │
                    │  + category + confidence %     │
                    │  + top 3 contributing features │
                    │  Latency: <500μs              │
                    └───────────────────────────────┘
```

### Why This Works

1. **Deterministic**: Same input → same output. Always. No sampling, no temperature.
2. **Fast**: Tree-based models do ~100 comparisons. In Go, that's <500μs per request.
3. **Explainable**: "Blocked because: URL entropy 7.8 (threshold 6.5), query param count 23 (unusual), TLD .xyz (high risk)". Not "I think this looks suspicious."
4. **Trainable offline**: Train on historical WAF JSONL logs. No GPU needed — CPU training in minutes.
5. **Compact**: Random Forest with 100 trees = ~500KB serialized. Fits in L2 cache.
6. **No new dependencies**: Pure Go implementation (gonum/stat, or hand-rolled — trees are just if/else).

---

## Layer 4: Feature Vector Engine

### The 32 Features We Can Extract Now (Go, zero deps)

```go
type RequestFeatures struct {
    // URL structure
    URLLength        float32  // normalized 0-1
    URLDepth         float32  // path segments count / 10
    URLEntropy       float32  // Shannon entropy / 8
    QueryParamCount  float32  // count / 20
    QueryEntropy     float32  // entropy of query string / 8
    HasDoubleEncode  float32  // 0 or 1
    HasNullByte      float32  // 0 or 1
    HasUnicodeEscape float32  // 0 or 1

    // Domain analysis
    DomainLength     float32  // len / 50
    DomainEntropy    float32  // Shannon / 6
    DomainDigitRatio float32  // digits / total chars
    ConsonantRatio   float32  // consonants / total
    TLDRiskScore     float32  // pre-computed per-TLD (0=.com, 1=.xyz)
    SubdomainDepth   float32  // count of dots / 5
    IsDirectIP       float32  // 0 or 1

    // Body analysis
    BodySize         float32  // log2(size) / 30
    BodyEntropy      float32  // Shannon / 8
    MIMEMismatch     float32  // declared vs actual MIME match (0 or 1)
    HasExecutable    float32  // magic bytes ELF/PE/MachO detected

    // Header analysis
    HeaderCount      float32  // count / 30
    HeaderOrderHash  float32  // hash of header names order (consistency)
    HasEmptyUA       float32  // 0 or 1
    UAIsScripting    float32  // curl/wget/python detected
    ContentLengthOk  float32  // CL matches body? 0 or 1

    // Behavioral (from heuristics state)
    RequestsLastMin  float32  // this IP's req/min / 100
    DistinctDestsMin float32  // unique destinations this minute / 50
    AvgInterReqDelay float32  // mean ms between requests / 10000
    IsBeaconing      float32  // beaconing score 0-1
    BytesOutRatio    float32  // out/in ratio for this IP / 10

    // Context
    HourOfDay        float32  // hour / 24 (nighttime = higher risk)
    IsWeekend        float32  // 0 or 1
    MethodEncoding   float32  // GET=0, POST=0.5, OTHER=1
}
```

**All computable in Go with zero external libraries.** The feature vector IS the innovation — not the model.

---

## Layer 5: Ensemble Models

### Model 1: Random Forest — Attack Classification

**Purpose**: Classify request into attack categories (SQLi, XSS, CMDi, traversal, SSRF, clean).

**Training data**: Historical WAF JSONL logs. Each blocked request = labeled positive. Each allowed = negative. We already have this data.

**Implementation in Go**:
```go
// A decision tree is just nested if/else
type Node struct {
    FeatureIndex int
    Threshold    float32
    Left, Right  *Node     // nil = leaf
    Class        int       // leaf: predicted class
    Confidence   float32   // leaf: probability
}

func (n *Node) Predict(features []float32) (class int, confidence float32) {
    if n.Left == nil { return n.Class, n.Confidence }
    if features[n.FeatureIndex] <= n.Threshold {
        return n.Left.Predict(features)
    }
    return n.Right.Predict(features)
}
```

100 trees × 15 depth = ~50K nodes = ~500KB in memory. Prediction: ~100 comparisons = **<10μs**.

### Model 2: Gradient Boosted Trees — Threat Scoring

**Purpose**: Continuous risk score 0.0-1.0. Higher = more suspicious.

**Why separate from RF**: Random Forest classifies (attack type). GBT scores (how suspicious overall). They complement each other.

**Training**: XGBoost offline (Python), export to Go-readable JSON format. Inference in Go.

### Model 3: Isolation Forest — Anomaly Detection

**Purpose**: Find requests that are "weird" even if they don't match known attack patterns. Zero-day detection.

**How**: Isolation Forest measures how easy it is to isolate a data point. Anomalies are isolated quickly (fewer splits). Normal traffic requires many splits.

**Key advantage**: Doesn't need labeled attack data. Trained purely on "normal" traffic. Anything that deviates significantly = anomaly.

**Implementation**: ~200 lines of Go. Each tree is a random partition. Anomaly score = average path length across trees.

### Ensemble Voting

```go
func (e *Ensemble) Score(features []float32) Decision {
    rfClass, rfConf := e.RandomForest.Predict(features)
    gbtScore := e.GradientBoosted.Score(features)
    ifoAnomaly := e.IsolationForest.AnomalyScore(features)

    // Weighted combination
    finalScore := 0.4*rfConf + 0.35*gbtScore + 0.25*ifoAnomaly

    return Decision{
        Block:      finalScore > e.Threshold, // default 0.85
        Score:      finalScore,
        Category:   rfClass,
        Confidence: rfConf,
        Anomaly:    ifoAnomaly,
        TopFeatures: e.TopContributors(features, 3), // SHAP-lite
    }
}
```

**Total inference time: <50μs.** That's 50x faster than our current regex engine.

---

## Training Pipeline (offline, no GPU)

```
┌─────────────────────────────────────────────────┐
│  1. Collect: WAF JSONL logs (already produced)   │
│     - Each request: URL, headers, body hash,     │
│       WAF decision, category, score              │
│                                                   │
│  2. Label: blocked = attack, allowed = clean      │
│     - Manual review of edge cases (FP/FN)         │
│                                                   │
│  3. Extract: Run feature extractor on each log    │
│     - Output: CSV with 32 features + label        │
│                                                   │
│  4. Train: Python script (sklearn/xgboost)        │
│     - Random Forest: 100 trees, max_depth=15      │
│     - GBT: 200 estimators, learning_rate=0.1      │
│     - Isolation Forest: 100 trees, contamination=0.01
│                                                   │
│  5. Export: Serialize trees to JSON/binary         │
│     - Go-readable format, ~500KB per model        │
│                                                   │
│  6. Deploy: Copy model files to /models/ volume   │
│     - Go backend loads on startup                 │
│     - Hot-reload via SIGHUP (no restart needed)   │
│                                                   │
│  Total training time: ~30 seconds on laptop CPU   │
│  Total model size: ~1.5MB (all 3 models)          │
│  Total inference RAM: ~5MB                        │
└─────────────────────────────────────────────────┘
```

### Training script (ships with project):
```bash
# One command to train from your own traffic
python3 tools/train_models.py --input data/waf_traffic.jsonl --output models/
```

The model learns YOUR network's patterns. Not generic internet traffic — YOUR actual servers, YOUR normal behavior. This is the ultimate personalization.

---

## Intent Router (Bonus: for UI assistance)

Instead of an LLM chatbot, build a **deterministic intent classifier** for the Dashboard:

```
User input: "Why is my server blocked?"
                    │
         ┌──────────▼──────────┐
         │  Intent Classifier   │
         │  (TF-IDF + SVM)      │
         │  ~100 intents         │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Intent: EXPLAIN_BLOCK │
         │  Entities: server=*    │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │  Handler (Go func)    │
         │  → query recent blocks │
         │  → format explanation  │
         │  → return structured   │
         └──────────────────────┘

Response: "192.168.100.5 was blocked 3 times in the last hour.
           Reason: SQL_INJECTION rule #14 triggered on URL parameter 'id'.
           Action: If this is legitimate, add the domain to whitelist."
```

**100 intents cover 95% of user questions.** TF-IDF + linear SVM trains in <1 second, classifies in <1μs. Zero hallucination — every response is a Go template filled with real data.

---

## Implementation Roadmap

### v2.3: Smart Summaries (Go templates)
**Effort: 4-6h | RAM: 0 extra | Latency: 0 extra**

- Daily security digest card on Dashboard
- Template-based: "3,412 inspected, 186 blocked, top threat: SQLi"
- No ML needed — just SQL aggregation + Go templates
- **Ships in next release**

### v2.4: Feature Vector Engine
**Effort: 6-8h | RAM: +5MB | Latency: +50μs**

- Extract 32 features per request in ICAP WAF
- Log features to JSONL for training data collection
- Feature vector exposed in `/api/waf/stats` for visibility
- **Runs alongside regex engine, doesn't replace it**

### v2.5: Ensemble Classifier
**Effort: 12-16h | RAM: +5MB | Latency: +50μs**

- Train RF + GBT + IsolationForest from collected features
- Ship `tools/train_models.py` for user self-training
- Ensemble runs in parallel with regex — both must agree to block (AND logic)
- Reduces false positives while maintaining detection rate
- **This is the "AI" that actually works**

### v3.0: Intent Router (UI assistant)
**Effort: 8-12h | RAM: +2MB**

- TF-IDF + SVM intent classifier for Dashboard chat
- 100 hand-crafted intents with Go template responses
- Deterministic, instant, zero hallucination
- "Why is X blocked?" → real answer from real data

---

## The Uncomfortable Truths

1. **Regex is not dead.** A well-curated regex ruleset catches known attacks with 100% precision and 0 latency. No ML model beats this for known patterns.

2. **ML's real value is anomaly detection.** Finding the unknown-unknowns that regex can't express. Isolation Forest is the right tool — not GPT.

3. **Feature engineering > model architecture.** The 32-feature vector we defined above is more valuable than any model choice. A good feature set makes even a linear classifier work.

4. **Train on YOUR data.** A model trained on your network's traffic for 1 week will outperform any pre-trained model because it knows what "normal" looks like for YOU.

5. **Two paths, always.** Regex (deterministic, fast) for blocking. ML (probabilistic, slow-er) for scoring and anomaly detection. They vote together. Neither has veto power alone.

6. **If you can't explain why it blocked, it shouldn't block.** Every decision must trace back to: which features, which model, which threshold. No black boxes in security.
