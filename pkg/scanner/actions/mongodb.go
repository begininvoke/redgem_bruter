package actions

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// MongoDBAction implements MongoDB-specific actions
type MongoDBAction struct {
	BaseAction
}

// NewMongoDBAction creates a new MongoDB action
func NewMongoDBAction() *MongoDBAction {
	return &MongoDBAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if MongoDB requires authentication
func (m *MongoDBAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := m.CheckPort(m.Host, m.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run MongoDB auth script
	output, err := m.RunNmapScript(m.Host, m.Port, "mongodb-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "auth") ||
		strings.Contains(output, "login")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force MongoDB
func (m *MongoDBAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := m.ReadServiceWordlist("mongodb")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"admin:password",
			"admin:123456",
			"root:root",
			"root:password",
			"root:123456",
			"mongodb:mongodb",
			"mongodb:password",
			"mongodb:123456",
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

		// Try to connect to MongoDB
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", m.Host, m.Port), m.Timeout)
		if err != nil {
			continue
		}

		// Send authentication request
		authCmd := fmt.Sprintf(`{"authenticate": 1, "user": "%s", "pwd": "%s", "mechanism": "SCRAM-SHA-1"}`, username, password)
		_, err = conn.Write([]byte(authCmd))
		if err != nil {
			conn.Close()
			continue
		}

		// Read response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(m.Timeout))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			response := string(buf[:n])
			if strings.Contains(response, "ok") && !strings.Contains(response, "AuthenticationFailed") {
				success = true
				successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
				conn.Close()
				break
			}
		}
		conn.Close()
	}

	if !success {
		return false, "Failed to brute force MongoDB with common credentials", nil
	}

	return true, successInfo, nil
}
