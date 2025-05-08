package actions

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLAction implements MySQL-specific actions
type MySQLAction struct {
	BaseAction
}

// NewMySQLAction creates a new MySQL action
func NewMySQLAction() *MySQLAction {
	return &MySQLAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MySQL requires authentication
func (m *MySQLAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run MySQL auth script
	output, err := m.RunNmapScript(m.Host, m.Port, "mysql-info")
	if err != nil {
		return false, "", err
	}

	// MySQL typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force MySQL
func (m *MySQLAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := m.ReadServiceWordlist("mysql")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"root:root",
			"root:",
			"admin:admin",
			"root:password",
			"admin:password",
			"root:123456",
			"admin:123456",
		}
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/mysql?timeout=%ds",
			username,
			password,
			m.Host,
			m.Port,
			int(m.Timeout.Seconds()))

		db, err := sql.Open("mysql", dsn)
		if err != nil {
			continue
		}

		// Set connection timeout
		db.SetConnMaxLifetime(m.Timeout)

		// Try to ping the database
		err = db.Ping()
		if err == nil {
			db.Close()
			success = true
			successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
			break
		}
		db.Close()
	}

	if !success {
		return false, "Failed to brute force MySQL with common credentials", nil
	}

	return true, successInfo, nil
}
