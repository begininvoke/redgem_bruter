package actions

import (
	"strings"
)

// NATSAction implements NATS service scanning
type NATSAction struct {
	BaseAction
}

// NewNATSAction creates a new NATS action
func NewNATSAction() *NATSAction {
	return &NATSAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if NATS requires authentication
func (n *NATSAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := n.CheckPort(n.Host, n.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run NATS auth script
	output, err := n.RunNmapScript(n.Host, n.Port, "nats-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "requires credentials") ||
		strings.Contains(output, "auth required")

	return requiresAuth, output, nil
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
