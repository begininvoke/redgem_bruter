package actions

import (
	"strings"
)

// MQTTAction implements MQTT service scanning
type MQTTAction struct {
	BaseAction
}

// NewMQTTAction creates a new MQTT action
func NewMQTTAction() *MQTTAction {
	return &MQTTAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MQTT requires authentication
func (m *MQTTAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run MQTT auth script
	output, err := m.RunNmapScript(m.Host, m.Port, "mqtt-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "requires credentials") ||
		strings.Contains(output, "auth required")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force MQTT credentials
func (m *MQTTAction) BruteForce() (bool, string, error) {
	// Run MQTT brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "mqtt-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
