package actions

import (
	"fmt"
	"strings"
)

// POP3Action implements POP3 service scanning
type POP3Action struct {
	BaseAction
}

// NewPOP3Action creates a new POP3 action
func NewPOP3Action() *POP3Action {
	return &POP3Action{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if POP3 requires authentication and potential vulnerabilities
func (p *POP3Action) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := p.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "POP3 2.3") || strings.Contains(version, "POP3 2.4") {
		vulnerable = true
	}

	// Run POP3-specific auth detection
	output, err := p.RunNmapScript(p.Host, p.Port, "pop3-capabilities")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("POP3 %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for POP3-specific vulnerabilities
func (p *POP3Action) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := p.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "POP3 2.3") || strings.Contains(version, "POP3 2.4") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := p.RunNmapScript(p.Host, p.Port, "pop3-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = p.RunNmapScript(p.Host, p.Port, "pop3-capabilities")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force POP3 credentials
func (p *POP3Action) BruteForce() (bool, string, error) {
	// Run POP3 brute force script
	output, err := p.RunNmapScript(p.Host, p.Port, "pop3-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
