package actions

import (
	"strings"
)

// NetdataAction implements Netdata service scanning
type NetdataAction struct {
	BaseAction
}

// NewNetdataAction creates a new Netdata action
func NewNetdataAction() *NetdataAction {
	return &NetdataAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Netdata requires authentication
func (n *NetdataAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := n.CheckPort(n.Host, n.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Netdata auth script
	output, err := n.RunNmapScript(n.Host, n.Port, "http-auth-finder")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "Netdata login")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Netdata credentials
func (n *NetdataAction) BruteForce() (bool, string, error) {
	// Run Netdata brute force script
	output, err := n.RunNmapScript(n.Host, n.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
