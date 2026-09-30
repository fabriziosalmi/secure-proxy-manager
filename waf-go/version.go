package main

// GitCommit is the source revision the binary was built from. The Dockerfile
// injects it with -ldflags -X main.GitCommit=$GIT_SHA; a plain `go build` leaves
// "unknown", which is how a binary that did not come from the release pipeline
// identifies itself (same convention as the backend's config.GitCommit).
var GitCommit = "unknown"
