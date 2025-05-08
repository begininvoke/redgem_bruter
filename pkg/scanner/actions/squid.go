package actions

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// SquidAction implements Squid proxy service scanning
type SquidAction struct {
	BaseAction
}

// NewSquidAction creates a new Squid action
func NewSquidAction() *SquidAction {
	return &SquidAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Squid proxy requires authentication
func (s *SquidAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := s.CheckPort(s.Host, s.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", s.Host, s.Port))
	if err != nil {
		return false, "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: s.Timeout,
	}

	// Try to connect through proxy without auth
	resp, err := client.Get("http://speedtest.llsapi.com")
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Check if proxy requires authentication
	requiresAuth := resp.StatusCode == http.StatusProxyAuthRequired ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Basic") ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Digest") ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "NTLM")

	// Check for Squid-specific headers
	if !requiresAuth {
		requiresAuth = strings.Contains(resp.Header.Get("Server"), "squid") ||
			strings.Contains(resp.Header.Get("X-Squid-Error"), "ERR_CACHE_ACCESS_DENIED")
	}

	return requiresAuth, fmt.Sprintf("Squid Proxy Status: %d", resp.StatusCode), nil
}

// BruteForce attempts to brute force Squid proxy credentials
func (s *SquidAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := s.ReadServiceWordlist("squid")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"admin:password",
			"admin:123456",
			"squid:squid",
			"squid:password",
			"proxy:proxy",
			"proxy:password",
			"root:root",
			"root:password",
			"user:user",
			"user:password",
		}
	}

	// Create HTTP client with proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", s.Host, s.Port))
	if err != nil {
		return false, "", err
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		// Set proxy authentication
		proxyURL.User = url.UserPassword(username, password)

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: s.Timeout,
		}

		// Try to connect through proxy
		resp, err := client.Get("http://speedtest.llsapi.com")
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check if authentication was successful
		if resp.StatusCode == http.StatusOK {
			success = true
			successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
			break
		}
	}

	if !success {
		// Try nmap script as fallback
		output, err := s.RunNmapScript(s.Host, s.Port, "http-proxy-brute")
		if err != nil {
			return false, "", err
		}

		success = strings.Contains(output, "Valid credentials") ||
			strings.Contains(output, "Login successful")

		if success {
			successInfo = output
		}
	}

	return success, successInfo, nil
}
