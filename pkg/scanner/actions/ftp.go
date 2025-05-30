package actions

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// FTPAction implements FTP service scanning
type FTPAction struct {
	BaseAction
}

// NewFTPAction creates a new FTP action
func NewFTPAction() *FTPAction {
	return &FTPAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if FTP requires authentication
func (f *FTPAction) CheckAuth() (bool, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", f.Host, f.Port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// Try anonymous login
	fmt.Fprintf(conn, "USER anonymous\r\n")
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	fmt.Fprintf(conn, "PASS anonymous\r\n")
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	if strings.Contains(response, "230") {
		return false, "FTP allows anonymous access", nil
	}

	return true, "FTP requires authentication", nil
}

// BruteForce attempts to brute force FTP credentials
func (f *FTPAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := f.ReadServiceWordlist("ftp")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"anonymous:anonymous",
			"anonymous:ftp",
			"anonymous:anonymous@",
			"anonymous:ftp@",
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

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", f.Host, f.Port), 5*time.Second)
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
			fmt.Fprintf(conn, "USER %s\r\n", username)
			response, err := reader.ReadString('\n')
			if err != nil {
				return
			}

			if !strings.HasPrefix(response, "331") {
				return
			}

			// Send password
			fmt.Fprintf(conn, "PASS %s\r\n", password)
			response, err = reader.ReadString('\n')
			if err != nil {
				return
			}

			if strings.HasPrefix(response, "230") {
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
