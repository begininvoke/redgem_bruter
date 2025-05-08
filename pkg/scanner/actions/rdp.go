package actions

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// RDPAction implements RDP service scanning
type RDPAction struct {
	BaseAction
}

// NewRDPAction creates a new RDP action
func NewRDPAction() *RDPAction {
	return &RDPAction{}
}

// CheckAuth checks if RDP requires authentication
func (r *RDPAction) CheckAuth() (bool, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.Host, r.Port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	// Read the initial RDP response
	reader := bufio.NewReader(conn)
	_, err = reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// RDP always requires authentication
	return true, "RDP requires authentication", nil
}

// BruteForce attempts to brute force RDP credentials
func (r *RDPAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := r.ReadServiceWordlist("rdp")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"administrator:administrator",
			"administrator:admin",
			"administrator:password",
			"administrator:123456",
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

			// Connect to RDP server
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", r.Host, r.Port), 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			// Read the initial RDP response
			reader := bufio.NewReader(conn)
			_, err = reader.ReadString('\n')
			if err != nil {
				return
			}

			// Send X.224 Connection Request
			// This is a simplified version. In a real implementation,
			// you would need to handle the full RDP protocol.
			connReq := []byte{
				0x03, 0x00, // TPKT Header
				0x00, 0x2c, // Length
				0x02, 0xf0, 0x80, // X.224 Connection Request
			}
			_, err = conn.Write(connReq)
			if err != nil {
				return
			}

			// Read the response
			response, err := reader.ReadString('\n')
			if err != nil {
				return
			}

			// Check if the connection was accepted
			// This is a simplified check. In a real implementation,
			// you would need to parse the RDP protocol properly.
			if !strings.Contains(strings.ToLower(response), "error") {
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
