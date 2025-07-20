package actions

import (
	"fmt"
	"strings"
)

// SMBAction implements SMB service scanning
type SMBAction struct {
	BaseAction
}

// NewSMBAction creates a new SMB action
func NewSMBAction() *SMBAction {
	return &SMBAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if SMB requires authentication and potential vulnerabilities
func (s *SMBAction) CheckAuth() (bool, string, bool, error) {
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
	if strings.Contains(version, "Samba 3.0") || strings.Contains(version, "Samba 3.1") {
		vulnerable = true
	}

	// Run SMB-specific auth detection
	output, err := s.RunNmapScript(s.Host, s.Port, "smb-enum-shares")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("SMB %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for SMB-specific vulnerabilities
func (s *SMBAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "Samba 3.0") || strings.Contains(version, "Samba 3.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := s.RunNmapScript(s.Host, s.Port, "smb-enum-shares")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = s.RunNmapScript(s.Host, s.Port, "smb-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = s.RunNmapScript(s.Host, s.Port, "smb-enum-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force SMB credentials
func (s *SMBAction) BruteForce() (bool, string, error) {
	// Run SMB brute force script
	output, err := s.RunNmapScript(s.Host, s.Port, "smb-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
