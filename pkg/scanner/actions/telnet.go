package actions

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// TelnetAction implements Telnet service scanning
type TelnetAction struct {
	BaseAction
}

// NewTelnetAction creates a new Telnet action
func NewTelnetAction() *TelnetAction {
	return &TelnetAction{}
}

// CheckAuth checks if Telnet requires authentication
func (t *TelnetAction) CheckAuth() (bool, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", t.Host, t.Port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// Check if login prompt is present
	if strings.Contains(strings.ToLower(response), "login") {
		return true, "Telnet requires authentication", nil
	}

	return false, "Telnet does not require authentication", nil
}

// BruteForce attempts to brute force Telnet credentials
func (t *TelnetAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := t.ReadServiceWordlist("telnet")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"root:root",
			"admin:admin",
			"root:password",
			"admin:password",
		}
	}

	// Create a semaphore to limit concurrent attempts
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	var success bool
	var successMsg string
	var mu sync.Mutex

	for _, cred := range credentials {
		wg.Add(1)
		go func(cred string) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			parts := strings.Split(cred, ":")
			if len(parts) != 2 {
				return
			}

			username, password := parts[0], parts[1]

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", t.Host, t.Port), 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			_, err = reader.ReadString('\n') // Read welcome message
			if err != nil {
				return
			}

			// Send username
			fmt.Fprintf(conn, "%s\r\n", username)
			response, err := reader.ReadString('\n')
			if err != nil {
				return
			}

			// Check for password prompt
			if !strings.Contains(strings.ToLower(response), "password") {
				return
			}

			// Send password
			fmt.Fprintf(conn, "%s\r\n", password)
			response, err = reader.ReadString('\n')
			if err != nil {
				return
			}

			// Check for successful login
			if !strings.Contains(strings.ToLower(response), "incorrect") && !strings.Contains(strings.ToLower(response), "invalid") {
				mu.Lock()
				success = true
				successMsg = fmt.Sprintf("Successfully authenticated with %s:%s", username, password)
				mu.Unlock()
			}
		}(cred)
	}

	wg.Wait()
	return success, successMsg, nil
}
