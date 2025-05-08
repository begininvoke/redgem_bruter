package actions

import (
	"strings"
)

// DockerAction implements Docker service scanning
type DockerAction struct {
	BaseAction
}

// NewDockerAction creates a new Docker action
func NewDockerAction() *DockerAction {
	return &DockerAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Docker requires authentication
func (d *DockerAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := d.CheckPort(d.Host, d.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Docker auth script
	output, err := d.RunNmapScript(d.Host, d.Port, "docker-version")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "unauthorized") ||
		strings.Contains(output, "access denied")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Docker credentials
func (d *DockerAction) BruteForce() (bool, string, error) {
	// Run Docker brute force script
	output, err := d.RunNmapScript(d.Host, d.Port, "docker-auth")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
