package actions

import (
	"strings"
)

// AFPAction implements AFP service scanning
type AFPAction struct {
	BaseAction
}

// NewAFPAction creates a new AFP action
func NewAFPAction() *AFPAction {
	return &AFPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if AFP requires authentication
func (a *AFPAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := a.CheckPort(a.Host, a.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run AFP auth script
	output, err := a.RunNmapScript(a.Host, a.Port, "afp-info")
	if err != nil {
		return false, "", err
	}

	// AFP typically requires authentication
	return true, output, nil
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
