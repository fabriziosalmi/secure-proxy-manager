package middleware

import "net/http"

// ErrorCodes is every value an error answer's code takes. The OpenAPI Error
// schema enumerates exactly these, so a client (the spm command, the MCP
// server) can branch on code instead of reading detail.
var ErrorCodes = []string{
	"invalid_request", "unauthorized", "forbidden", "token_scope", "not_found",
	"conflict", "gone", "too_large", "unprocessable", "rate_limited",
	"internal_error", "upstream_unreachable", "unavailable",
	// Specific failures that say more than their status.
	"trigger_write_failed", "reload_failed", "clear_cache_failed",
}

// ErrorCode is the code an error answer of this status carries when nothing
// more specific is said.
func ErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusGone:
		return "gone"
	case http.StatusRequestEntityTooLarge:
		return "too_large"
	case http.StatusUnprocessableEntity:
		return "unprocessable"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusBadGateway:
		return "upstream_unreachable"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	if status >= 500 {
		return "internal_error"
	}
	return "invalid_request"
}

// ErrorBody is the body of an error answer: {status, code, detail}.
func ErrorBody(status int, detail string) map[string]string {
	return map[string]string{"status": "error", "code": ErrorCode(status), "detail": detail}
}

// WriteError answers an error with its status, code and detail.
func WriteError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, ErrorBody(status, detail))
}
