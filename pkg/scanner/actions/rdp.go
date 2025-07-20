package actions

import (
	"fmt"
	"strings"
)

// RDPAction implements RDP service scanning
type RDPAction struct {
	BaseAction
}

// NewRDPAction creates a new RDP action
func NewRDPAction() *RDPAction {
	return &RDPAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if RDP requires authentication and potential vulnerabilities
func (r *RDPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := r.CheckPort(r.Host, r.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Windows XP") || strings.Contains(version, "Windows 2000") {
		vulnerable = true
	}

	// Run RDP-specific auth detection
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-enum-encryption")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("RDP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for RDP-specific vulnerabilities
func (r *RDPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Windows XP") || strings.Contains(version, "Windows 2000") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for BlueKeep vulnerability
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-vuln-ms12-020")
	if err == nil && strings.Contains(output, "VULNERABLE") {
		vulnerabilities = append(vulnerabilities, "BlueKeep vulnerability (CVE-2019-0708)")
	}

	// Check for default credentials
	output, err = r.RunNmapScript(r.Host, r.Port, "rdp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = r.RunNmapScript(r.Host, r.Port, "rdp-enum-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force RDP credentials
func (r *RDPAction) BruteForce() (bool, string, error) {
	// Run RDP brute force script
	output, err := r.RunNmapScript(r.Host, r.Port, "rdp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
