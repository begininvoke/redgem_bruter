package actions

import (
	"strings"
)

// TeamCityAction implements TeamCity service scanning
type TeamCityAction struct {
	BaseAction
}

// NewTeamCityAction creates a new TeamCity action
func NewTeamCityAction() *TeamCityAction {
	return &TeamCityAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if TeamCity requires authentication
func (t *TeamCityAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := t.CheckPort(t.Host, t.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run TeamCity auth script
	output, err := t.RunNmapScript(t.Host, t.Port, "http-auth-finder")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "TeamCity login")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force TeamCity credentials
func (t *TeamCityAction) BruteForce() (bool, string, error) {
	// Run TeamCity brute force script
	output, err := t.RunNmapScript(t.Host, t.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
