package config

// AppVersion is the semantic version of this backend build.
const AppVersion = "3.13.0"

// APIVersion is the version of the HTTP CONTRACT — request and response shapes,
// status codes, header semantics. It is deliberately separate from AppVersion:
// AppVersion advances on every patch release, including UI- and docs-only ones,
// so a caller branching on it has to re-verify against releases that changed
// nothing it depends on. Bump this ONLY when a shape changes, and say what
// changed in docs/api/reference.md (SECURE-API-03).
const APIVersion = "1"

// GitCommit is injected at build time with -ldflags -X. It is empty in a plain
// `go build`, which is the honest answer for a binary that was not built by the
// release pipeline (SECURE-BLD-02).
var GitCommit = "unknown"
