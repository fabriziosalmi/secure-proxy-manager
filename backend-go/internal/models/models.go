// Package models contains request/response structs used across handlers.
//
// The `validate:` tags are enforced by internal/validate, which every handler
// runs against the decoded body. They were inert for the life of the package —
// no validator was ever registered — so the length bounds in particular
// described limits nothing applied (SECURE-DOM-02). Three types were removed
// with that fix rather than wired up: RestoreConfigRequest, SettingUpdate and
// SettingsBulkUpdate had no reference outside this file, and two of them
// described request shapes the API does not accept (BulkUpdate takes a bare
// object, not {"settings": {...}}), so they read as a contract and were not one.
package models

type LoginRequest struct {
	Username string `json:"username" validate:"required,min=1,max=128"`
	Password string `json:"password" validate:"required,min=1,max=128"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=8"`
}

type IPListItem struct {
	IP          string `json:"ip"          validate:"required,max=50"`
	Description string `json:"description" validate:"max=500"`
}

type DomainListItem struct {
	Domain      string `json:"domain"      validate:"required,max=253"`
	Description string `json:"description" validate:"max=500"`
}

type EgressAllowItem struct {
	Entry       string `json:"entry"       validate:"required,max=253"`
	Description string `json:"description" validate:"max=500"`
}

type InternalAlert struct {
	EventType string         `json:"event_type" validate:"required"`
	Message   string         `json:"message"    validate:"required"`
	Level     string         `json:"level"`
	Details   map[string]any `json:"details"`
}

type ImportBlacklistRequest struct {
	Type    string `json:"type"    validate:"required,oneof=ip domain"`
	URL     string `json:"url"     validate:"omitempty,max=2048"`
	Content string `json:"content" validate:"omitempty,max=52428800"`
}

type ImportGeoBlacklistRequest struct {
	Countries []string `json:"countries" validate:"required,min=1,max=50"`
}

type BulkDeleteRequest struct {
	IDs []int64 `json:"ids" validate:"required,min=1"`
}
