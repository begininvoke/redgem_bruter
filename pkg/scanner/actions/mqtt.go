package actions

import (
	"fmt"
	"strings"
)

// MQTTAction implements MQTT service scanning
type MQTTAction struct {
	BaseAction
}

// NewMQTTAction creates a new MQTT action
func NewMQTTAction() *MQTTAction {
	return &MQTTAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if MQTT requires authentication and potential vulnerabilities
func (m *MQTTAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "MQTT 3.1") || strings.Contains(version, "MQTT 3.1.1") {
		vulnerable = true
	}

	// Run MQTT-specific auth detection
	output, err := m.RunNmapScript(m.Host, m.Port, "mqtt-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("MQTT %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for MQTT-specific vulnerabilities
func (m *MQTTAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := m.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "MQTT 3.1") || strings.Contains(version, "MQTT 3.1.1") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default credentials
	output, err := m.RunNmapScript(m.Host, m.Port, "mqtt-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	// Check for weak encryption
	output, err = m.RunNmapScript(m.Host, m.Port, "ssl-cert")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
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
