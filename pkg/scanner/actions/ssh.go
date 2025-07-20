package actions

import (
	"fmt"
	"strings"
)

// SSHAction implements SSH service scanning
type SSHAction struct {
	BaseAction
}

// NewSSHAction creates a new SSH action
func NewSSHAction() *SSHAction {
	return &SSHAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if SSH requires authentication and potential vulnerabilities
func (s *SSHAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version and potential vulnerabilities
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "7.2") || strings.Contains(version, "7.3") {
		vulnerable = true
	}

	// Run SSH-specific auth detection
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh-auth-methods")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "publickey") ||
		strings.Contains(output, "password") ||
		strings.Contains(output, "keyboard-interactive")

	return requiresAuth, fmt.Sprintf("SSH %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for SSH-specific vulnerabilities
func (s *SSHAction) CheckVulnerability() (bool, string, error) {
	// Get banner and version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "7.2") || strings.Contains(version, "7.3") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for weak algorithms
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh2-enum-algos")
	if err == nil {
		if strings.Contains(output, "arcfour") || strings.Contains(output, "blowfish") {
			vulnerabilities = append(vulnerabilities, "Weak encryption algorithms supported")
		}
	}

	// Check for default credentials
	output, err = s.RunNmapScript(s.Host, s.Port, "ssh-default-accounts")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force SSH credentials
func (s *SSHAction) BruteForce() (bool, string, error) {
	// Run SSH brute force script
	output, err := s.RunNmapScript(s.Host, s.Port, "ssh-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
