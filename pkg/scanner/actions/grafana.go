package actions

import (
	"strings"
)

// GrafanaAction implements Grafana service scanning
type GrafanaAction struct {
	BaseAction
}

// NewGrafanaAction creates a new Grafana action
func NewGrafanaAction() *GrafanaAction {
	return &GrafanaAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Grafana requires authentication
func (g *GrafanaAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := g.CheckPort(g.Host, g.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Grafana auth script
	output, err := g.RunNmapScript(g.Host, g.Port, "http-auth-finder")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "Grafana login")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Grafana credentials
func (g *GrafanaAction) BruteForce() (bool, string, error) {
	// Run Grafana brute force script
	output, err := g.RunNmapScript(g.Host, g.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
