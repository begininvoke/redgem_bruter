package actions

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// POP3Action implements POP3 service scanning
type POP3Action struct {
	BaseAction
}

// NewPOP3Action creates a new POP3 action
func NewPOP3Action() *POP3Action {
	return &POP3Action{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if POP3 requires authentication
func (p *POP3Action) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Try to connect to POP3 server
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// Check if server requires authentication
	if strings.Contains(strings.ToUpper(response), "+OK") {
		// Try to get capabilities
		fmt.Fprintf(conn, "CAPA\r\n")
		response, err = reader.ReadString('\n')
		if err != nil {
			return false, "", err
		}

		// Check if AUTH is supported
		if strings.Contains(strings.ToUpper(response), "AUTH") {
			return true, "POP3 requires authentication", nil
		}
	}

	return false, "POP3 does not require authentication", nil
}

// BruteForce attempts to brute force POP3 credentials
func (p *POP3Action) BruteForce() (bool, string, error) {
	// Run POP3 brute force script
	output, err := p.RunNmapScript(p.Host, p.Port, "pop3-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
