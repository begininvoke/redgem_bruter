package actions

import (
	"strings"
)

// MemcachedAction implements Memcached service scanning
type MemcachedAction struct {
	BaseAction
}

// NewMemcachedAction creates a new Memcached action
func NewMemcachedAction() *MemcachedAction {
	return &MemcachedAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Memcached requires authentication
func (m *MemcachedAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Memcached auth script
	output, err := m.RunNmapScript(m.Host, m.Port, "memcached-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "SASL authentication") ||
		strings.Contains(output, "auth required")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Memcached credentials
func (m *MemcachedAction) BruteForce() (bool, string, error) {
	// Run Memcached brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "memcached-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
