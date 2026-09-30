package main

import (
	"log/slog"
	"os"
	"strings"
)

// setupLogging makes structured records the WAF's log format, matching the
// backend: JSON on stderr, or text when LOG_FORMAT=pretty. slog.SetDefault also
// routes the standard library's log package through the same handler, so the
// lines that still use log.Printf come out as records with a msg field instead
// of a second, free-text format in the same stream.
//
// Identifiers an operator filters on (client_ip, event_id, categories, rules,
// url, the rejected variable and value) are fields, not text inside a message.
func setupLogging() {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var h slog.Handler = slog.NewJSONHandler(os.Stderr, opts)
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "pretty") {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
