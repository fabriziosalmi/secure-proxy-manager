package handlers

import "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"

// SysInfo supplies the update and CVE state the status endpoint reports.
//
// Two handlers used to call workers.GetUpdateInfo() and workers.GetCVEInfo()
// directly — mutex-guarded package globals written by background goroutines.
// The state was race-safe, so this is a design wart rather than a bug, but it
// meant those endpoints could not be exercised against a chosen state without
// mutating process-wide globals, and the dependency was invisible at the
// composition root, where every other edge is explicit (SECURE-ARCH-04).
type SysInfo interface {
	UpdateInfo() workers.UpdateInfo
	CVEInfo() workers.CVEInfo
}

// WorkerSysInfo is the production implementation, reading the state the
// background checkers maintain.
type WorkerSysInfo struct{}

func (WorkerSysInfo) UpdateInfo() workers.UpdateInfo { return workers.GetUpdateInfo() }
func (WorkerSysInfo) CVEInfo() workers.CVEInfo       { return workers.GetCVEInfo() }
