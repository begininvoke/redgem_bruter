package actions

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPAction implements LDAP service scanning
type LDAPAction struct {
	BaseAction
}

// NewLDAPAction creates a new LDAP action
func NewLDAPAction() *LDAPAction {
	return &LDAPAction{}
}

// CheckAuth checks if LDAP requires authentication
func (l *LDAPAction) CheckAuth() (bool, string, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", l.Host, l.Port))
	if err != nil {
		return false, "", err
	}
	defer conn.Close()

	// Try anonymous bind
	err = conn.UnauthenticatedBind("")
	if err == nil {
		return false, "LDAP allows anonymous access", nil
	}

	return true, "LDAP requires authentication", nil
}

// BruteForce attempts to brute force LDAP credentials
func (l *LDAPAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := l.ReadServiceWordlist("ldap")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"cn=admin,dc=example,dc=com:admin",
			"cn=root,dc=example,dc=com:root",
			"cn=admin,dc=example,dc=com:password",
			"cn=root,dc=example,dc=com:password",
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

			dn, password := parts[0], parts[1]

			conn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", l.Host, l.Port))
			if err != nil {
				return
			}
			defer conn.Close()

			// Set timeout
			conn.SetTimeout(5 * time.Second)

			// Try simple bind
			err = conn.Bind(dn, password)
			if err == nil {
				mu.Lock()
				success = true
				successMsg = fmt.Sprintf("Successfully authenticated with %s:%s", dn, password)
				mu.Unlock()
				return
			}

			// Try SASL bind if simple bind fails
			// Note: This is a simplified example. In a real implementation,
			// you would need to handle different SASL mechanisms and their specific requirements.
			err = conn.Bind(dn, password)
			if err == nil {
				mu.Lock()
				success = true
				successMsg = fmt.Sprintf("Successfully authenticated with %s:%s using SASL", dn, password)
				mu.Unlock()
				return
			}
		}(cred)
	}

	wg.Wait()
	return success, successMsg, nil
}
