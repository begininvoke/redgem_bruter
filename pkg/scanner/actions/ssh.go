package actions

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHAction implements SSH service scanning
type SSHAction struct {
	BaseAction
}

// NewSSHAction creates a new SSH action
func NewSSHAction() *SSHAction {
	return &SSHAction{}
}

// CheckAuth checks if SSH requires authentication
func (s *SSHAction) CheckAuth() (bool, string, error) {
	// Try to connect to SSH
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password(""),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), config)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return true, "SSH requires authentication", nil
		}
		return false, "", err
	}

	return false, "SSH does not require authentication", nil
}

// BruteForce attempts to brute force SSH credentials
func (s *SSHAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := s.ReadServiceWordlist("ssh")
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

			config := &ssh.ClientConfig{
				User: username,
				Auth: []ssh.AuthMethod{
					ssh.Password(password),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         5 * time.Second,
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), config)
			if err == nil {
				client.Close()
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
