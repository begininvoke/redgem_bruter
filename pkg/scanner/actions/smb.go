package actions

import (
	"strings"
)

// SMBAction implements SMB service scanning
type SMBAction struct {
	BaseAction
}

// NewSMBAction creates a new SMB action
func NewSMBAction() *SMBAction {
	return &SMBAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if SMB requires authentication
func (s *SMBAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run SMB auth script
	output, err := s.RunNmapScript(s.Host, s.Port, "smb-enum-shares")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "access denied") ||
		strings.Contains(output, "permission denied")

	return requiresAuth, output, nil
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
