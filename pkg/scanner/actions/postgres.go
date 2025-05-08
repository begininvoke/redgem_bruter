package actions

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"
)

// PostgresAction implements PostgreSQL-specific actions
type PostgresAction struct {
	BaseAction
}

// NewPostgresAction creates a new PostgreSQL action
func NewPostgresAction() *PostgresAction {
	return &PostgresAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if PostgreSQL requires authentication
func (p *PostgresAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run PostgreSQL auth script
	output, err := p.RunNmapScript(p.Host, p.Port, "pgsql-info")
	if err != nil {
		return false, "", err
	}

	// PostgreSQL typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force PostgreSQL
func (p *PostgresAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := p.ReadServiceWordlist("postgres")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"postgres:postgres",
			"postgres:admin",
			"postgres:password",
			"postgres:123456",
			"admin:admin",
			"admin:password",
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

		connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
			p.Host,
			p.Port,
			username,
			password,
			int(p.Timeout.Seconds()))

		db, err := sql.Open("postgres", connStr)
		if err != nil {
			continue
		}

		// Set connection timeout
		db.SetConnMaxLifetime(p.Timeout)

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
		return false, "Failed to brute force PostgreSQL with common credentials", nil
	}

	return true, successInfo, nil
}
