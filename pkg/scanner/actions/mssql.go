package actions

import (
	"strings"
)

// MSSQLAction implements MSSQL service scanning
type MSSQLAction struct {
	BaseAction
}

// NewMSSQLAction creates a new MSSQL action
func NewMSSQLAction() *MSSQLAction {
	return &MSSQLAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MSSQL requires authentication
func (m *MSSQLAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run MSSQL auth script
	output, err := m.RunNmapScript(m.Host, m.Port, "ms-sql-info")
	if err != nil {
		return false, "", err
	}

	// MSSQL typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force MSSQL credentials
func (m *MSSQLAction) BruteForce() (bool, string, error) {
	// Run MSSQL brute force script
	output, err := m.RunNmapScript(m.Host, m.Port, "ms-sql-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
