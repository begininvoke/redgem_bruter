package actions

import (
	"fmt"
	"strings"
)

// SMTPAction implements SMTP service scanning
type SMTPAction struct {
	BaseAction
}

// NewSMTPAction creates a new SMTP action
func NewSMTPAction() *SMTPAction {
	return &SMTPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if SMTP requires authentication and potential vulnerabilities
func (s *SMTPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "Sendmail 8.12") || strings.Contains(version, "Postfix 2.11") {
		vulnerable = true
	}

	// Run SMTP-specific auth detection
	output, err := s.RunNmapScript(s.Host, s.Port, "smtp-commands")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "AUTH") ||
		strings.Contains(output, "LOGIN") ||
		strings.Contains(output, "PLAIN")

	return requiresAuth, fmt.Sprintf("SMTP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for SMTP-specific vulnerabilities
func (s *SMTPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Sendmail 8.12") || strings.Contains(version, "Postfix 2.11") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for open relay
	output, err := s.RunNmapScript(s.Host, s.Port, "smtp-open-relay")
	if err == nil && strings.Contains(output, "VULNERABLE") {
		vulnerabilities = append(vulnerabilities, "Open relay detected")
	}

	// Check for default credentials
	output, err = s.RunNmapScript(s.Host, s.Port, "smtp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for VRFY/EXPN
	output, err = s.RunNmapScript(s.Host, s.Port, "smtp-commands")
	if err == nil && (strings.Contains(output, "VRFY") || strings.Contains(output, "EXPN")) {
		vulnerabilities = append(vulnerabilities, "VRFY/EXPN commands enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force SMTP credentials
func (s *SMTPAction) BruteForce() (bool, string, error) {
	// Run SMTP brute force script
	output, err := s.RunNmapScript(s.Host, s.Port, "smtp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
