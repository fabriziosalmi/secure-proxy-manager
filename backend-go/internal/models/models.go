// Package models contains request/response structs used across handlers.
package models

type LoginRequest struct {
	Username string `json:"username" validate:"required,min=1,max=128"`
	Password string `json:"password" validate:"required,min=1,max=128"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=8"`
}

type RestoreConfigRequest struct {
	Config map[string]string `json:"config" validate:"required"`
}

type IPListItem struct {
	IP          string `json:"ip"          validate:"required,max=50"`
	Description string `json:"description" validate:"max=500"`
}

type DomainListItem struct {
	Domain      string `json:"domain"      validate:"required,max=253"`
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

type SettingUpdate struct {
	Value string `json:"value" validate:"max=10000"`
}

type SettingsBulkUpdate struct {
	Settings map[string]string `json:"settings" validate:"required"`
}

type BulkDeleteRequest struct {
	IDs []int64 `json:"ids" validate:"required,min=1"`
}
