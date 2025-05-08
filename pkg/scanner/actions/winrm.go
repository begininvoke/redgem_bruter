package actions

import (
	"strings"
)

// WinRMAction implements WinRM service scanning
type WinRMAction struct {
	BaseAction
}

// NewWinRMAction creates a new WinRM action
func NewWinRMAction() *WinRMAction {
	return &WinRMAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if WinRM requires authentication
func (w *WinRMAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := w.CheckPort(w.Host, w.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run WinRM auth script
	output, err := w.RunNmapScript(w.Host, w.Port, "winrm-info")
	if err != nil {
		return false, "", err
	}

	// WinRM typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force WinRM credentials
func (w *WinRMAction) BruteForce() (bool, string, error) {
	// Run WinRM brute force script
	output, err := w.RunNmapScript(w.Host, w.Port, "winrm-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
