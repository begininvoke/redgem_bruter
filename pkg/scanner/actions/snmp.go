package actions

import (
	"strings"
)

// SNMPAction implements SNMP service scanning
type SNMPAction struct {
	BaseAction
}

// NewSNMPAction creates a new SNMP action
func NewSNMPAction() *SNMPAction {
	return &SNMPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if SNMP requires authentication
func (s *SNMPAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run SNMP auth script
	output, err := s.RunNmapScript(s.Host, s.Port, "snmp-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "community string") ||
		strings.Contains(output, "SNMPv3")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force SNMP community strings
func (s *SNMPAction) BruteForce() (bool, string, error) {
	// Run SNMP brute force script
	output, err := s.RunNmapScript(s.Host, s.Port, "snmp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid community string") ||
		strings.Contains(output, "SNMP access granted")

	return success, output, nil
}
