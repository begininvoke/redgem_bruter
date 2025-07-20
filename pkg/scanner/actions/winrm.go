package actions

import (
	"fmt"
	"strings"
)

// WinRMAction implements WinRM service scanning
type WinRMAction struct {
	BaseAction
}

// NewWinRMAction creates a new WinRM action
func NewWinRMAction() *WinRMAction {
	return &WinRMAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if WinRM requires authentication and potential vulnerabilities
func (w *WinRMAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := w.CheckPort(w.Host, w.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := w.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "WinRM 1.0") || strings.Contains(version, "WinRM 2.0") {
		vulnerable = true
	}

	// Run WinRM-specific auth detection
	output, err := w.RunNmapScript(w.Host, w.Port, "winrm-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("WinRM %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for WinRM-specific vulnerabilities
func (w *WinRMAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := w.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "WinRM 1.0") || strings.Contains(version, "WinRM 2.0") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := w.RunNmapScript(w.Host, w.Port, "winrm-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = w.RunNmapScript(w.Host, w.Port, "winrm-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
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
