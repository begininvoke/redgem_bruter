package actions

import (
	"strings"
)

// CouchDBAction implements CouchDB service scanning
type CouchDBAction struct {
	BaseAction
}

// NewCouchDBAction creates a new CouchDB action
func NewCouchDBAction() *CouchDBAction {
	return &CouchDBAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if CouchDB requires authentication
func (c *CouchDBAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := c.CheckPort(c.Host, c.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run CouchDB auth script
	output, err := c.RunNmapScript(c.Host, c.Port, "http-auth-finder")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "CouchDB login")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force CouchDB credentials
func (c *CouchDBAction) BruteForce() (bool, string, error) {
	// Run CouchDB brute force script
	output, err := c.RunNmapScript(c.Host, c.Port, "http-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
