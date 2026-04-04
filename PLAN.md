# PLAN.md — Secure Proxy Manager: Analisi Completa e Piano d'Azione

> Analisi generata il 2026-04-04 — Versione progetto: 3.1.1 (v3.0.0 release 2026-03-28)
> Metodologia: Extreme Thinking — ogni aspetto esaminato a fondo, dal livello architetturale al singolo mutex.

---

## Indice

1. [Panoramica Progetto](#1-panoramica-progetto)
2. [Architettura Alto Livello](#2-architettura-alto-livello)
3. [Wiring & Integrazione Servizi](#3-wiring--integrazione-servizi)
4. [Analisi Basso Livello (Backend Go)](#4-analisi-basso-livello-backend-go)
5. [Analisi Basso Livello (WAF Go)](#5-analisi-basso-livello-waf-go)
6. [UI/UX Frontend](#6-uiux-frontend)
7. [Performance](#7-performance)
8. [Security](#8-security)
9. [Logiche Applicative](#9-logiche-applicative)
10. [Rispetto Standard](#10-rispetto-standard)
11. [Capacità di Innovazione](#11-capacità-di-innovazione)
12. [Findings Critici](#12-findings-critici)
13. [Piano d'Azione (TODO)](#13-piano-dazione-todo)
14. [Metriche di Riferimento](#14-metriche-di-riferimento)

---

## 1. Panoramica Progetto

**Cos'è**: Appliance di sicurezza di rete integrata — "Pi-hole + WAF + egress firewall" in un unico sistema.

**Stack tecnologico**:
| Layer | Tecnologia | Versione |
|-------|-----------|----------|
| Backend API | Go (chi router, zerolog, modernc/sqlite) | 1.24 |
| WAF Engine | Go (go-icap, regex rules, heuristics) | 1.22 |
| Frontend | React 19, TypeScript 5.9, Vite 8, Tailwind | Latest |
| Proxy | Squid | 5.9 |
| DNS | dnsmasq | Alpine 3.21 |
| Orchestrazione | Docker Compose (6 servizi) | - |
| Reverse Proxy | Nginx | 1.27.4 |

**Target**: Homelab, self-hosted, SMB security. Supporto Raspberry Pi (ARM64) + x86.

**Dimensioni codebase**:
- Backend Go: ~4,700 LOC handlers + ~1,500 LOC infrastruttura
- WAF Go: ~2,000+ LOC (171 regole, 7 euristiche, 3 ML-lite detector)
- Frontend: ~3,400 LOC React/TypeScript
- Test: 38 file Go test + E2E shell (104 check)
- Coverage: Backend 67%, WAF 70%

---

## 2. Architettura Alto Livello

### Diagramma dei Servizi

```
                    ┌──────────────┐
                    │   Internet   │
                    └──────┬───────┘
                           │ :80/:443
                    ┌──────▼───────┐
                    │  Nginx (web) │  TLS termination, static files
                    │   64M RAM    │
                    └──┬───────┬───┘
                       │       │
              /api/*   │       │  static assets
                       │       │
                ┌──────▼───┐   │
                │ Backend  │   │  REST API, Auth, DB
                │ Go :5000 │   │  128M RAM
                │ (SQLite) │   │
                └──────────┘   │
                               │
    ┌──────────────────────────┘
    │
    │  Client traffic via proxy
    │
┌───▼──────────┐     ICAP      ┌────────────┐
│ Squid Proxy  │◄──────────────►│  WAF Go    │
│   :3128      │                │  :1344     │
│  512M RAM    │                │  256M RAM  │
└──────────────┘                └────────────┘
    │
    │  DNS resolution
    ▼
┌──────────┐
│ dnsmasq  │  DNS sinkhole
│  :53/UDP │
│  64M RAM │
└──────────┘
```

### Punti di Forza Architetturali
- **Separazione chiara**: Ogni servizio ha responsabilità singola
- **Zero CGO**: Backend usa modernc/sqlite (pure Go) → build statico 16MB
- **Multi-arch**: linux/amd64 + linux/arm64
- **Resource limits**: Container limitati (totale ~1.75 CPU, 1GB RAM)
- **Health checks**: Tutti i servizi hanno healthcheck Docker

### Debolezze Architetturali
- **SQLite single-writer**: MaxOpenConns=1 limita la concorrenza in scrittura
- **In-memory state**: Rate limits, JWT blacklist, WebSocket tokens non persistiti → persi al restart
- **Accoppiamento Docker**: Backend comunica via Docker socket per SIGHUP ai container
- **Nessun service mesh**: Comunicazione interna senza mTLS

---

## 3. Wiring & Integrazione Servizi

### Flusso di una Richiesta HTTP Client

```
1. Client configura proxy :3128
2. Squid riceve CONNECT request
3. Squid invia a WAF via ICAP (REQMOD) :1344
4. WAF: safe cache check → rule matching (171 regole) → heuristics → scoring
5. WAF risponde: Allow (204) o Block (200 con block page)
6. Se Allow: Squid forward a destinazione
7. Squid riceve risposta → ICAP RESPMOD → WAF ispeziona body (PII, exfil)
8. Squid logga in access.log
9. Backend log_tailer worker parsa access.log → INSERT in SQLite
10. UI Dashboard mostra statistiche via React Query (polling 10s)
```

### Integrazione Backend ↔ WAF
- Backend chiama `http://waf:8080/stats` per metriche WAF
- Backend chiama `http://waf:8080/categories` per categorie WAF
- WAF chiama `http://backend:5000/api/internal/alert` per notifiche (fire-and-forget)
- Nessuna autenticazione intra-servizio (rete Docker isolata)

### Integrazione Backend ↔ Squid/dnsmasq
- Backend scrive blacklist su file condivisi via volume mount
- Backend invia SIGHUP via Docker socket per reload configurazioni
- Squid access.log letto dal backend log_tailer worker (polling 500ms)

### Integrazione Frontend ↔ Backend
- Axios con base URL `/api`, timeout 120s
- JWT Bearer token in header Authorization
- WebSocket per log streaming (`/api/ws/logs?token=...`)
- React Query per caching (staleTime 10-30s)

### Problemi di Wiring Trovati
- [ ] **Nessun retry/circuit breaker** nelle chiamate WAF → Backend alerts
- [ ] **Polling file-based** per log_tailer (500ms sleep loop) vs inotify/fsnotify
- [ ] **Docker socket dependency** per signal handling → fragile se permessi cambiano
- [ ] **No health check cross-service**: Backend non verifica che WAF sia attivo prima di servire

---

## 4. Analisi Basso Livello (Backend Go)

### Struttura Package (Eccellente)
```
backend-go/internal/
├── auth/       # JWT, bcrypt, rate limiting, WS tokens (3 RWMutex)
├── config/     # Env vars, JWT secret management
├── database/   # SQLite WAL, migrations, atomic exports
├── docker/     # Docker Engine API (read-only socket)
├── handlers/   # 19 file, ~4,700 LOC, 70+ endpoint
├── middleware/  # Auth, CORS, security headers, request ID, body limit
├── models/     # Request/response structs con validation tags
├── websocket/  # Hub pattern per broadcast real-time
└── workers/    # 5 background workers (log, retention, refresh, update, CVE)
```

### Pattern di Concorrenza
| Componente | Meccanismo | Note |
|-----------|-----------|------|
| JWT Blacklist | sync.RWMutex | Cleanup ogni 10 min |
| Rate Limiter | sync.RWMutex | Per-IP tracking |
| WS Tokens | sync.RWMutex | One-time, 2 min TTL |
| WS Hub | sync.RWMutex + channel | Drop slow clients |
| Notify Queue | Buffered channel (256) | Non-blocking send |
| Workers | time.NewTicker | No context cancellation ⚠️ |

### Problemi Trovati

**Severità ALTA**:
- [ ] **Workers senza context cancellation**: `log_tailer`, `blacklist_refresh` ecc. girano in loop infinito senza possibilità di cancellation graceful. Solo `time.Sleep()` senza `select` su context.Done().

**Severità MEDIA**:
- [ ] **~20+ errori ignorati** (`//nolint:errcheck`): `database.Audit()`, `os.WriteFile()`, `stmt.Exec()` in loop. Alcuni sono benigni, ma file write errors dovrebbero essere gestiti.
- [ ] **No context propagation** nelle query DB: `db.Query()` senza `ctx` → impossibile cancellare query lente.
- [ ] **Nessuna paginazione** su alcune analytics query: `TopDomains` può tornare dataset enormi.
- [ ] **SQL string interpolation** per table names: 4 location con `fmt.Sprintf` per nomi tabella. Mitigato da allowlist hardcoded, ma pattern fragile.

**Severità BASSA**:
- [ ] **WebSocket CheckOrigin** accetta tutto (`return true`). Mitigato da token auth, ma non best practice.
- [ ] **Hard-coded timeouts**: Tutti i timeout HTTP sono hardcoded (non configurabili).
- [ ] **Nessun tipo errore strutturato**: Tutti gli errori sono stringhe, no custom error types.
- [ ] **Validation tags non enforced**: `models.go` ha tag `validate:` ma nessun validator automatico li applica.

### Qualità del Codice
- **Punti di forza**: Idiomatic Go, package layout pulito, zero CGO, dependency minime
- **Metriche**: 67% test coverage, 27 test file, table-driven tests
- **Dead code**: Nessuno trovato — tutto è importato e usato

---

## 5. Analisi Basso Livello (WAF Go)

### Architettura Engine

```
Request → isLANHost? → SafeCache? → Normalize → Tier1 Rules → Score Check
                                                → Tier2 Rules → Score Check
                                                → Tier3 Rules → Score Check
                                    → Heuristics (7 check) → Score Check
                                    → ML-lite (DGA, Typosquat) → Final Score
                                    → Block/Allow → Log → Notify
```

### Metriche Regole
- 171 regole regex in 21 categorie di sicurezza
- Tier-based execution: 11µs (Tier 1 early-exit) → 176µs (tutte le regole)
- Scoring system: threshold configurabile (default 10 punti)
- Dual-scan: raw + normalized payloads

### Euristiche Comportamentali
| ID | Nome | Finestra | Soglia |
|----|------|----------|--------|
| H1 | Entropia Shannon | Per-request | 7.5 |
| H2 | Beaconing | 300s per-IP | 5+ req timing regolare |
| H3 | PII Counter | Per-response | 5 items |
| H4 | Destination Sharding | 60s per-IP | 50+ host unici |
| H5 | Header Morphing | Per-sessione | Cambiamento = flag |
| H6 | Protocol Ghosting | Per-request | Protocolli incapsulati |
| H7 | Sequence Validation | Per-sessione | Sequenze impossibili |

### ML-lite Detectors
- **DGA Detection**: Analisi bigramma per domini generati algoritmicamente
- **Typosquatting**: Distanza di Levenshtein per domini sospetti
- **Safe URL Cache**: Hash-based set (FNV-64a), 50K entries, 5 min TTL, LRU eviction

### Problemi WAF
- [ ] **go-icap dependency**: `v0.0.0-20151011115316` — 11 anni senza aggiornamento
- [ ] **No regex precompilation caching**: Le regex sono compilate con `regexp.MustCompile` ma a init, non a runtime — OK
- [ ] **Body inspection limitata**: Max 1MB per request/response body
- [ ] **Heuristic state unbounded growth**: Mitigato da cleanup 60s, ma sotto attacco DDoS la mappa `clientStates` potrebbe crescere

---

## 6. UI/UX Frontend

### Struttura
- 6 pagine principali: Dashboard, Blacklists, Logs, Threats, Settings, Login
- Componenti riutilizzabili: Card primitives, GlobalSearch (Cmd+K), SetupWizard, ClientSetup
- Dark theme-only (nessun light mode)

### Punti di Forza UX
- **Command palette** (Cmd+K): Ricerca globale con shortcut tastiera 1-5
- **Setup Wizard**: Onboarding multi-step per nuovi utenti
- **Presets**: Template configurazione rapida (Basic/Family/Standard/Security/Advanced)
- **Client Setup**: Istruzioni per 5 piattaforme (Win/Mac/Linux/iOS/Android) con PAC file
- **Regex Playground**: Sandbox per test regole WAF
- **Real-time logs**: WebSocket con reconnect esponenziale
- **Skeleton loading**: Placeholder animati durante caricamento
- **IP tagging**: Badge inline con localStorage

### Problemi UX/UI

**Severità ALTA**:
- [ ] **Accessibilità carente**: Nessun ARIA live region per toast, nessun focus trapping nei modal, chart senza testo alternativo, nessun skip link, loading spinner senza aria-busy
- [ ] **Nessun test frontend**: Zero file `.test.tsx` o `.spec.tsx`. Nessun unit test React.
- [ ] **Nessuna internazionalizzazione (i18n)**: Tutto hardcoded in inglese

**Severità MEDIA**:
- [ ] **No light mode**: Solo tema scuro, potrebbe non essere accessibile per tutti
- [ ] **Nessun React.lazy**: Tutte le pagine caricate eagerly (976KB bundle)
- [ ] **Prop drilling**: Nessun Context API per auth state → prop drilling
- [ ] **`confirm()` nativo**: Azioni distruttive usano `window.confirm()` del browser invece di modal custom
- [ ] **Brand logo non cliccabile**: Non naviga alla Dashboard

**Severità BASSA**:
- [ ] **No RTL support**: Nessun supporto per lingue destra-sinistra
- [ ] **CSP permissiva**: `'unsafe-inline'` e `'unsafe-eval'` nel CSP (necessario per React/Tailwind, ma limitabile con nonces)
- [ ] **Recharts bundle size**: Libreria pesante, potrebbe essere sostituita con alternative leggere

### Validazione Form (Buona)
- Zod 4.3.6 per schema validation
- IP/CIDR: Validazione per ottetto (0-255)
- Domini: RFC 1035 compliant (max 253 chars, label validation)
- Password: 8+ chars, numero, carattere speciale con indicatori real-time
- Port: Regex + range 1-65535
- Idempotency-Key header per prevenire duplicati

---

## 7. Performance

### Metriche Chiave
| Metrica | Valore | Rating |
|---------|--------|--------|
| Throughput (LAN) | ~750 req/s | Eccellente |
| Throughput (Internet) | ~336 req/s @ 1000 client | Buono |
| WAF overhead | <1ms per request | Eccellente |
| P50 latency (con ICAP) | 107ms | Buono |
| P95 latency | 883ms | Accettabile |
| Backend memory | ~20MB (128M limit) | Eccellente |
| Binary size | 16MB (zero dependencies) | Eccellente |
| Cache hit rate | 92% (50K safe URLs) | Molto Buono |
| Attack detection | 31/31 (100%) | Perfetto |
| False positive rate | 0/7 (0%) | Perfetto |

### Confronto Python → Go
| Metrica | Python (v1.x) | Go (v3.x) | Miglioramento |
|---------|---------------|-----------|---------------|
| RAM | 150MB | 20MB | 7.5x |
| Latency | 180ms | 107ms | 1.7x |
| Binary | N/A (interpreter) | 16MB single file | ∞ |
| Concurrency | GIL-limited | Native goroutines | ∞ |

### Colli di Bottiglia Identificati
- [ ] **SQLite query su DB grande** (67MB, 500K+ log): 450-480ms per aggregazioni → necessita index tuning
- [ ] **Log tailer polling-based**: 500ms sleep loop anziché inotify → latenza notifica fino a 500ms
- [ ] **Nessun pprof endpoint**: Impossibile fare profiling continuo in produzione
- [ ] **Nessun connection pooling HTTP**: Ogni chiamata esterna crea nuova connessione
- [ ] **File I/O sincrono** per export blacklist: Potrebbe bloccare handler durante export grandi

### Ottimizzazioni Presenti (Buone)
- Safe URL cache con TTL e LRU eviction
- Tier-based rule execution con early exit
- Atomic counters (`atomic.Int64`) per statistiche lock-free
- Buffered channel per traffic logging (4096 items, non-blocking)
- Drop slow WebSocket clients (no cascading failures)
- `io.LimitReader` per body inspection (1MB max)
- WAL mode SQLite per concurrent reads

---

## 8. Security

### Matrice di Rischio
| Categoria | Rischio | Stato | Dettagli |
|-----------|---------|-------|----------|
| Autenticazione | Basso | ✅ | JWT + bcrypt + rate limiting + constant-time compare |
| SQL Injection | Basso | ✅ | Query parametrizzate, table names da allowlist |
| Command Injection | Basso | ✅ | Solo comandi hardcoded (no user input) |
| XSS | Basso | ✅ | React escaping + CSP (ma `unsafe-inline` presente) |
| CSRF | Basso | ✅ | Mitigato da Bearer token (no cookies) |
| SSRF | Basso | ✅ | Validazione completa con DNS pinning |
| Secrets | Basso | ✅ | No hardcoded credentials, env vars required |
| TLS/SSL | Basso | ✅ | TLS 1.2/1.3, ciphers forti, HSTS |
| CORS | Basso | ✅ | Allowlist implementata, WebSocket origin check attivo |
| Rate Limiting | Basso | ✅ | Globale 20 req/s per IP + login-specific |
| Session Mgmt | Basso | ✅ | Blacklist persistita su SQLite |
| Logging Sensibile | Basso | ✅ | Token cifrati con AES-256-GCM |

### Problemi Security Trovati

**Severità ALTA** — TUTTI RISOLTI:
- [x] ~~**Plaintext password fallback**~~: bcrypt prioritario, plaintext solo first-boot
- [x] ~~**Token notifiche non cifrati**~~: AES-256-GCM encryption at rest
- [x] ~~**JWT blacklist in-memory**~~: Persistita su SQLite con TTL cleanup

**Severità MEDIA** — MAGGIORANZA RISOLTI:
- [x] ~~**Rate limiting solo su login**~~: Globale token bucket 20 req/s per IP
- [x] ~~**No gosec in CI/CD**~~: gosec + npm audit in pipeline
- [x] ~~**No npm audit in CI**~~: Aggiunto
- [x] ~~**CSP permissiva**~~: Rimossi `unsafe-eval` e `connect-src *`
- [ ] **No refresh token**: Utenti devono ri-autenticarsi ogni 8h
- [ ] **Docker socket mount**: Anche se read-only, espone l'API Docker al backend
- [ ] **No audit completo**: Non tutte le azioni admin sono loggate nell'audit trail

**Severità BASSA** — MAGGIORANZA RISOLTI:
- [x] ~~**WebSocket origin check disabilitato**~~: Validato contro CORS allowlist
- [x] ~~**Self-signed cert 10 anni**~~: Ridotto a 1 anno
- [ ] **No SBOM**: Nessun Software Bill of Materials generato

---

## 9. Logiche Applicative

### Logiche Core

**Blacklist Management**:
- Import da URL con SSRF protection + retry (3 tentativi, backoff esponenziale)
- Import da testo (incolla lista)
- Import geo-block per codice paese
- Export atomico su file (temp file + rename) → zero torn reads da Squid
- Whitelist exclusion applicata automaticamente
- Propagazione SIGHUP a Squid/dnsmasq dopo modifica

**WAF Scoring**:
- Anomaly scoring additivo: ogni regola aggiunge punti
- Threshold configurabile (default 10)
- Tier execution: stop alla prima soglia raggiunta
- Dual scan: payload raw + normalizzato (URL decode, case fold, whitespace strip)
- Tar-pitting: 10s delay dopo 3+ block/minuto per IP

**Analytics**:
- Shadow IT discovery (35+ categorie SaaS)
- User Agent analysis (metodi HTTP + tipi servizio)
- File extension analysis (Web, Images, Code, Archives)
- Timeline con bucket orari
- Security score 0-100 basato su feature abilitate

**Notifiche**:
- Queue asincrona (256 items)
- Canali: Webhook, Gotify, ntfy, Telegram, Teams
- Retry 3x con backoff esponenziale (1s, 2s, 4s) — aggiunto in v3.1

### Problemi nelle Logiche
- [x] ~~**Nessun retry notifiche**~~: 3x retry con backoff esponenziale (v3.1)
- [ ] **Security score statico**: Basato solo su toggle abilitati, non su stato reale sicurezza
- [ ] **Shadow IT detection simplistica**: Basata su pattern URL, no deep packet inspection
- [ ] **No rate limiting su import**: Un utente può importare liste enormi senza limiti
- [ ] **Geo-block senza aggiornamento**: Liste IP per paese non vengono aggiornate automaticamente

---

## 10. Rispetto Standard

### Standard Rispettati ✅
| Standard | Compliance | Note |
|----------|-----------|------|
| OWASP Top 10 | 10/10 | Rate limiting globale aggiunto in v3.1 |
| Go Project Layout | ✅ | `cmd/`, `internal/`, idiomatic |
| HTTP/REST | ✅ | Status codes corretti, JSON API |
| Docker Best Practices | ✅ | Multi-stage build, non-root, health checks |
| TLS 1.2/1.3 | ✅ | Protocolli moderni, cipher forti |
| HSTS | ✅ | 1 anno con includeSubDomains |
| CORS | ✅ | Origin allowlist (no wildcard) |
| DNS RFC 1035 | ✅ | Validazione domini conforme |
| JWT RFC 7519 | ✅ | HS256, claims standard |
| bcrypt | ✅ | Cost 10, constant-time compare |
| Semantic Versioning | ✅ | CHANGELOG.md dettagliato |

### Standard Non Rispettati ⚠️
| Standard | Gap | Impatto |
|----------|-----|---------|
| WCAG 2.1 AA | Accessibilità frontend carente | Alto per utenti disabili |
| i18n (ISO 639) | Nessuna localizzazione | Limita adozione internazionale |
| OpenAPI 3.0 | No spec formale (solo /api/docs) | Difficile generare SDK client |
| GDPR | Parziale (masking log, no DPO, no consent) | Rischio compliance EU |
| SOC 2 | No audit trail completo, no encryption at rest | Limita adozione enterprise |
| SBOM (SPDX/CycloneDX) | Nessuno | Limita supply chain transparency |
| CSP Level 3 | unsafe-inline/unsafe-eval | XSS mitigation indebolita |
| OAuth 2.0 / OIDC | No SSO support | Limita integrazione enterprise |

---

## 11. Capacità di Innovazione

### Innovazioni Presenti 🌟
1. **ML-lite detection senza ML framework**: DGA via bigramma, typosquat via Levenshtein — zero dipendenze ML
2. **Tier-based rule execution**: Early exit intelligente che taglia 95% del tempo di valutazione
3. **Safe URL cache**: Approccio pragmatico che elimina 92% delle valutazioni ripetute
4. **7 euristiche comportamentali**: Beaconing, ghosting, morphing — detection avanzata senza signature
5. **Tar-pitting adattivo**: Rallenta attaccanti ripetuti invece di bloccarli (più utile per intelligence)
6. **Zero-CGO SQLite**: `modernc.org/sqlite` permette build statico cross-platform
7. **Setup Wizard + Presets**: Abbatte drasticamente la curva di apprendimento
8. **Shadow IT Discovery**: Feature tipica di prodotti enterprise a 6 cifre
9. **Client Setup multi-platform**: Genera istruzioni specifiche per 5 OS + PAC file
10. **Atomic file export**: Pattern temp-file+rename per zero downtime su Squid reload

### Opportunità di Innovazione Future
- [ ] **eBPF integration**: Packet inspection a livello kernel per performance 10x
- [ ] **WASM rules engine**: Regole custom compilabili in WebAssembly per sandboxing
- [ ] **Distributed state via Redis/etcd**: Scalabilità orizzontale
- [ ] **AI-based anomaly detection**: Pattern learning su traffico normale
- [ ] **GraphQL API**: Alternativa a REST per query flessibili dalla UI
- [ ] **Plugin system**: Estensibilità tramite plugin Go compilati
- [ ] **Encrypted DNS (DoH/DoT)**: Supporto DNS over HTTPS/TLS
- [ ] **OpenTelemetry**: Distributed tracing per debug cross-service
- [ ] **YARA rules support**: Import regole YARA per malware detection avanzata

---

## 12. Findings Critici

### TOP 10 Issues per Priorità

| # | Severità | Area | Issue | Stato |
|---|----------|------|-------|-------|
| 1 | ~~🔴 ALTA~~ | Security | ~~Plaintext password fallback~~ | ✅ Risolto v3.1 |
| 2 | ~~🔴 ALTA~~ | Security | ~~Token notifiche in plaintext~~ | ✅ Risolto v3.1 (AES-256-GCM) |
| 3 | 🔴 ALTA | UX | Zero test frontend (nessun .test.tsx) | ⏳ Fase 3 |
| 4 | 🔴 ALTA | UX | Accessibilità WCAG non rispettata | ⏳ Fase 3 |
| 5 | ~~🟡 MEDIA~~ | Backend | ~~Workers senza context cancellation~~ | ✅ Risolto v3.1 |
| 6 | ~~🟡 MEDIA~~ | Security | ~~JWT blacklist in-memory~~ | ✅ Risolto v3.1 (SQLite) |
| 7 | ~~🟡 MEDIA~~ | Security | ~~No gosec/npm audit in CI/CD~~ | ✅ Risolto v3.1 |
| 8 | ~~🟡 MEDIA~~ | Perf | ~~Query analytics lente~~ | ✅ Risolto v3.1 (3 index) |
| 9 | 🟡 MEDIA | Standard | No OpenAPI spec | ⏳ Backlog |
| 10 | ~~🟡 MEDIA~~ | Wiring | ~~No circuit breaker~~ | ✅ Risolto v3.1 |

---

## 13. Piano d'Azione (TODO)

### Fase 1 — Quick Wins (1-2 settimane) ✅ COMPLETATA

- [x] **Deprecare plaintext password fallback** in auth.go — bcrypt prioritario, plaintext solo se hash non esiste
- [x] **Aggiungere gosec + npm audit + backend tests** al workflow CI/CD (`.github/workflows/ci.yml`)
- [x] **Fix WebSocket CheckOrigin**: Validare origin contro CORS allowlist
- [x] **Aggiungere context.Context** a tutti i worker goroutines per graceful shutdown
- [x] **Aggiungere pprof endpoint** (`/debug/pprof/`) protetto da auth in backend
- [x] **Index SQLite compositi**: `idx_proxy_logs_ts_ip`, `idx_proxy_logs_ts_dest`, `idx_proxy_logs_status`
- [x] **Aggiungere LIMIT clause** a analytics query (UserAgents, FileExtensions)
- [x] **Ridurre self-signed cert validity** da 10 anni a 1 anno
- [x] **Caricare AdminPasswordHash dal DB** all'avvio (era mancante nel main.go)

### Fase 2 — Hardening (2-4 settimane) ✅ COMPLETATA

- [x] **Cifrare token sensibili nel DB** (Gotify, Telegram, webhook URL) con AES-256-GCM — nuovo package `internal/crypto`
- [x] **Persistere JWT blacklist** su SQLite con TTL-based cleanup — tabella `jwt_blacklist`, load on startup
- [x] **Aggiungere rate limiting globale** su tutti gli endpoint (token bucket per IP, 20 req/s, burst 60)
- [x] **Implementare circuit breaker** per chiamate WAF (3 failures → open 30s) — `middleware/circuitbreaker.go`
- [x] **Aggiungere retry con backoff** per notifiche fallite (3 tentativi, 1s/2s/4s backoff esponenziale)
- [x] **Tightening CSP**: Rimossi `unsafe-eval` e `connect-src *` → `script-src 'self'; connect-src 'self' ws: wss:`
- [ ] **Generare OpenAPI 3.0 spec** da handler definitions
- [ ] **Aggiungere SBOM generation** (CycloneDX) nel build

### Fase 3 — UX & Quality (4-8 settimane)

- [ ] **Setup testing frontend**: Vitest + React Testing Library
- [ ] **Scrivere test per ogni pagina**: Dashboard, Blacklists, Logs, Settings, Threats
- [ ] **Accessibilità WCAG 2.1 AA**:
  - [ ] ARIA live regions per toast notification
  - [ ] Focus trapping nei modal
  - [ ] Testo alternativo per chart Recharts
  - [ ] Skip link a main content
  - [ ] `aria-busy` su loading spinners
  - [ ] Keyboard navigation per tabelle
- [ ] **Aggiungere React.lazy** per code splitting pagine
- [ ] **Light mode toggle** (Tailwind dark: class + toggle button)
- [ ] **Sostituire `confirm()` nativo** con modal custom accessibili
- [ ] **i18n framework** (react-i18next) con inglese e italiano
- [ ] **Enforce validation tags** con go-playground/validator nel backend

### Fase 4 — Scalabilità & Innovazione (8+ settimane)

- [ ] **Migrare log tailer a fsnotify** per event-driven log parsing
- [ ] **OpenTelemetry integration** per distributed tracing
- [ ] **OAuth 2.0 / OIDC** per SSO enterprise
- [ ] **Redis-backed state** (rate limits, JWT blacklist, cache) per multi-instance
- [ ] **GraphQL endpoint** come alternativa a REST per dashboard query complesse
- [ ] **DNS over HTTPS (DoH)** support in dnsmasq replacement
- [ ] **YARA rules import** per malware detection avanzata
- [ ] **Plugin system** per regole WAF custom compilate in Go
- [ ] **Aggiornare go-icap** o fork con manutenzione (last update: 2015)

---

## 14. Metriche di Riferimento

### Stato Attuale (post v3.1)
| Metrica | Pre v3.1 | Post v3.1 | Target |
|---------|----------|-----------|--------|
| Backend test coverage | 67% | ~70% (+crypto pkg) | 80% |
| WAF test coverage | 70% | 70% | 85% |
| Frontend test coverage | 0% | 0% | 60% |
| Security detection rate | 100% (31/31) | 100% | Mantenere |
| False positive rate | 0% (0/7) | 0% | Mantenere |
| P50 latency | 107ms | ~100ms (index) | <100ms |
| Memory footprint | 20MB | 20MB | Mantenere |
| Throughput (LAN) | 750 req/s | 750 req/s | 1000 req/s |
| WCAG compliance | Parziale | Parziale | AA |
| OpenAPI spec | Assente | Assente | 3.0 completa |
| i18n lingue | 1 (EN) | 1 (EN) | 3 (EN, IT, ES) |
| CI security scanning | Assente | ✅ gosec + npm audit | Mantenere |
| Encryption at rest | ❌ | ✅ AES-256-GCM | Mantenere |
| JWT blacklist persist | ❌ | ✅ SQLite | Mantenere |
| Global rate limiting | ❌ | ✅ 20 req/s/IP | Mantenere |
| Circuit breaker | ❌ | ✅ WAF calls | Mantenere |

### KPI Post-Implementazione Piano
- [x] ~~Zero plaintext password support in auth chain~~ — bcrypt prioritario
- [x] ~~100% endpoint con rate limiting~~ — globale token bucket
- [x] ~~JWT blacklist sopravvive a restart container~~ — SQLite persistence
- [x] ~~Token sensibili cifrati at-rest~~ — AES-256-GCM
- [ ] Frontend test coverage > 60%
- [ ] Lighthouse accessibility score > 90
- [ ] OpenAPI spec auto-generata da codice
- [ ] SBOM generato per ogni release

---

> **Nota**: Questo piano è basato sull'analisi del codice al 2026-04-04. Le priorità possono cambiare in base a feedback utenti, incident di sicurezza, o requisiti di compliance. Rivedere mensilmente.
