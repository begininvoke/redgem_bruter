package actions

import (
	"fmt"
	"strings"
)

// SNMPAction implements SNMP service scanning
type SNMPAction struct {
	BaseAction
}

// NewSNMPAction creates a new SNMP action
func NewSNMPAction() *SNMPAction {
	return &SNMPAction{
		BaseAction: BaseAction{},
	}
}

// CheckAuth checks if SNMP requires authentication and potential vulnerabilities
func (s *SNMPAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "SNMP v1") || strings.Contains(version, "SNMP v2c") {
		vulnerable = true
	}

	// Run SNMP-specific auth detection
	output, err := s.RunNmapScript(s.Host, s.Port, "snmp-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "login required") ||
		strings.Contains(output, "credentials required")

	return requiresAuth, fmt.Sprintf("SNMP %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for SNMP-specific vulnerabilities
func (s *SNMPAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := s.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "SNMP v1") || strings.Contains(version, "SNMP v2c") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for default community strings
	output, err := s.RunNmapScript(s.Host, s.Port, "snmp-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default community strings found")
	}

	// Check for weak encryption
	output, err = s.RunNmapScript(s.Host, s.Port, "snmp-encryption")
	if err == nil && strings.Contains(output, "Weak encryption") {
		vulnerabilities = append(vulnerabilities, "Weak encryption enabled")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force SNMP credentials
func (s *SNMPAction) BruteForce() (bool, string, error) {
	// Run SNMP brute force script
	output, err := s.RunNmapScript(s.Host, s.Port, "snmp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}

func (s *SNMPAction) GetSNMPInfo() (string, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return "", err
	}
	if !open {
		return "Port closed", nil
	}

	// Run multiple SNMP scripts to gather comprehensive information
	scripts := []string{
		"snmp-info",           // Basic SNMP information
		"snmp-sysdescr",       // System description
		"snmp-interfaces",     // Network interfaces
		"snmp-netstat",        // Network statistics
		"snmp-processes",      // Running processes
		"snmp-win32-services", // Windows services (if applicable)
		"snmp-win32-shares",   // Windows shares (if applicable)
		"snmp-win32-software", // Installed software (if applicable)
		"snmp-win32-users",    // Windows users (if applicable)
	}

	var allOutput strings.Builder
	for _, script := range scripts {
		output, err := s.RunNmapScript(s.Host, s.Port, script)
		if err != nil {
			continue // Skip failed scripts but continue with others
		}
		allOutput.WriteString(output)
		allOutput.WriteString("\n")
	}

	return allOutput.String(), nil
}
