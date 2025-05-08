package actions

import (
	"strings"
)

// DB2Action implements DB2 service scanning
type DB2Action struct {
	BaseAction
}

// NewDB2Action creates a new DB2 action
func NewDB2Action() *DB2Action {
	return &DB2Action{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if DB2 requires authentication
func (d *DB2Action) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := d.CheckPort(d.Host, d.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run DB2 auth script
	output, err := d.RunNmapScript(d.Host, d.Port, "db2-info")
	if err != nil {
		return false, "", err
	}

	// DB2 typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force DB2 credentials
func (d *DB2Action) BruteForce() (bool, string, error) {
	// Run DB2 brute force script
	output, err := d.RunNmapScript(d.Host, d.Port, "db2-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
