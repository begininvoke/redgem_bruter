package actions

import (
	"fmt"
	"strings"
)

// NATSAction implements NATS service scanning
type NATSAction struct {
	BaseAction
}

// NewNATSAction creates a new NATS action
func NewNATSAction() *NATSAction {
	return &NATSAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if NATS requires authentication and potential vulnerabilities
func (n *NATSAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := n.CheckPort(n.Host, n.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := n.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "NATS 1.0") || strings.Contains(version, "NATS 1.1") {
		vulnerable = true
	}

	// Run NATS-specific auth detection
	output, err := n.RunNmapScript(n.Host, n.Port, "nats-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("NATS %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for NATS-specific vulnerabilities
func (n *NATSAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := n.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "NATS 1.0") || strings.Contains(version, "NATS 1.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := n.RunNmapScript(n.Host, n.Port, "nats-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = n.RunNmapScript(n.Host, n.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force NATS credentials
func (n *NATSAction) BruteForce() (bool, string, error) {
	// Run NATS brute force script
	output, err := n.RunNmapScript(n.Host, n.Port, "nats-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
