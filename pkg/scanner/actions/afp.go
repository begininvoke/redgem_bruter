package actions

import (
	"fmt"
	"strings"
)

// AFPAction implements AFP service scanning
type AFPAction struct {
	BaseAction
}

// NewAFPAction creates a new AFP action
func NewAFPAction() *AFPAction {
	return &AFPAction{
		BaseAction: BaseAction{}, // Initialize without dereferencing
	}
}

// CheckAuth checks if AFP requires authentication and potential vulnerabilities
func (a *AFPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := a.CheckPort(a.Host, a.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := a.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "AFP 2.2") || strings.Contains(version, "AFP 2.3") {
		vulnerable = true
	}

	// Run AFP-specific auth detection
	output, err := a.RunNmapScript(a.Host, a.Port, "afp-showmount")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("AFP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for AFP-specific vulnerabilities
func (a *AFPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := a.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "AFP 2.2") || strings.Contains(version, "AFP 2.3") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for guest access
	output, err := a.RunNmapScript(a.Host, a.Port, "afp-showmount")
	if err == nil && strings.Contains(output, "Guest access") {
		vulnerabilities = append(vulnerabilities, "Guest access allowed")
	}

	// Check for default credentials
	output, err = a.RunNmapScript(a.Host, a.Port, "afp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = a.RunNmapScript(a.Host, a.Port, "afp-enum-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force AFP credentials
func (a *AFPAction) BruteForce() (bool, string, error) {
	// Run AFP brute force script
	output, err := a.RunNmapScript(a.Host, a.Port, "afp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
