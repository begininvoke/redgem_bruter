package actions

import (
	"fmt"
	"strings"
)

// TelnetAction implements Telnet service scanning
type TelnetAction struct {
	BaseAction
}

// NewTelnetAction creates a new Telnet action
func NewTelnetAction() *TelnetAction {
	return &TelnetAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Telnet requires authentication and potential vulnerabilities
func (t *TelnetAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := t.CheckPort(t.Host, t.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := t.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "BSD") || strings.Contains(version, "Linux") {
		vulnerable = true
	}

	// Run Telnet-specific auth detection
	output, err := t.RunNmapScript(t.Host, t.Port, "telnet-encryption")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "Login required") ||
		strings.Contains(output, "Username:") ||
		strings.Contains(output, "Password:")

	return requiresAuth, fmt.Sprintf("Telnet %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Telnet-specific vulnerabilities
func (t *TelnetAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := t.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "BSD") || strings.Contains(version, "Linux") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for encryption
	output, err := t.RunNmapScript(t.Host, t.Port, "telnet-encryption")
	if err == nil && strings.Contains(output, "No encryption") {
		vulnerabilities = append(vulnerabilities, "No encryption (credentials sent in plaintext)")
	}

	// Check for default credentials
	output, err = t.RunNmapScript(t.Host, t.Port, "telnet-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Telnet credentials
func (t *TelnetAction) BruteForce() (bool, string, error) {
	// Run Telnet brute force script
	output, err := t.RunNmapScript(t.Host, t.Port, "telnet-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
