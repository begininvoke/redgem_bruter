package actions

import (
	"fmt"
	"strings"
)

// VNCAction implements VNC service scanning
type VNCAction struct {
	BaseAction
}

// NewVNCAction creates a new VNC action
func NewVNCAction() *VNCAction {
	return &VNCAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if VNC requires authentication and potential vulnerabilities
func (v *VNCAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := v.CheckPort(v.Host, v.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := v.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "VNC 3.3") || strings.Contains(version, "VNC 3.8") {
		vulnerable = true
	}

	// Run VNC-specific auth detection
	output, err := v.RunNmapScript(v.Host, v.Port, "vnc-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("VNC %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for VNC-specific vulnerabilities
func (v *VNCAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := v.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "VNC 3.3") || strings.Contains(version, "VNC 3.8") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := v.RunNmapScript(v.Host, v.Port, "vnc-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = v.RunNmapScript(v.Host, v.Port, "vnc-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force VNC credentials
func (v *VNCAction) BruteForce() (bool, string, error) {
	// Run VNC brute force script
	output, err := v.RunNmapScript(v.Host, v.Port, "vnc-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
