package actions

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// SMTPAction implements SMTP service scanning
type SMTPAction struct {
	BaseAction
}

// NewSMTPAction creates a new SMTP action
func NewSMTPAction() *SMTPAction {
	return &SMTPAction{}
}

// CheckAuth checks if SMTP requires authentication
func (s *SMTPAction) CheckAuth() (bool, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), 5*time.Second)
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// Send EHLO to get supported authentication methods
	fmt.Fprintf(conn, "EHLO example.com\r\n")
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, "", err
	}

	// Check if AUTH is supported
	if strings.Contains(strings.ToUpper(response), "AUTH") {
		return true, "SMTP requires authentication", nil
	}

	return false, "SMTP does not require authentication", nil
}

// BruteForce attempts to brute force SMTP credentials
func (s *SMTPAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := s.ReadServiceWordlist("smtp")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"root:root",
			"postmaster:postmaster",
			"postmaster:password",
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

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port), 5*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			_, err = reader.ReadString('\n') // Read welcome message
			if err != nil {
				return
			}

			// Send EHLO to get supported authentication methods
			fmt.Fprintf(conn, "EHLO example.com\r\n")
			response, err := reader.ReadString('\n')
			if err != nil {
				return
			}

			// Try different authentication methods
			authMethods := []string{"PLAIN", "LOGIN", "CRAM-MD5"}
			for _, method := range authMethods {
				if !strings.Contains(strings.ToUpper(response), method) {
					continue
				}

				var authCmd string
				switch method {
				case "PLAIN":
					auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", username, password)))
					authCmd = fmt.Sprintf("AUTH PLAIN %s\r\n", auth)
				case "LOGIN":
					userB64 := base64.StdEncoding.EncodeToString([]byte(username))
					passB64 := base64.StdEncoding.EncodeToString([]byte(password))
					authCmd = fmt.Sprintf("AUTH LOGIN %s %s\r\n", userB64, passB64)
				case "CRAM-MD5":
					challenge := "challenge" // In real implementation, get this from server
					h := hmac.New(md5.New, []byte(password))
					h.Write([]byte(challenge))
					response := base64.StdEncoding.EncodeToString(h.Sum(nil))
					authCmd = fmt.Sprintf("AUTH CRAM-MD5 %s %s\r\n", username, response)
				}

				fmt.Fprintf(conn, authCmd)
				response, err := reader.ReadString('\n')
				if err != nil {
					continue
				}

				if strings.HasPrefix(response, "235") {
					mu.Lock()
					success = true
					successMsg = fmt.Sprintf("Successfully authenticated with %s:%s using %s", username, password, method)
					mu.Unlock()
					return
				}
			}
		}(cred)
	}

	wg.Wait()
	return success, successMsg, nil
}
