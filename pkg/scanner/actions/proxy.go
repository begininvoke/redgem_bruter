package actions

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ProxyAction implements HTTP proxy service scanning
type ProxyAction struct {
	BaseAction
}

// NewProxyAction creates a new proxy action
func NewProxyAction() *ProxyAction {
	return &ProxyAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if proxy requires authentication
func (p *ProxyAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Create HTTP client with proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", p.Host, p.Port))
	if err != nil {
		return false, "", err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: p.Timeout,
	}

	// Try to connect through proxy without auth
	resp, err := client.Get("http://example.com")
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	// Check if proxy requires authentication
	requiresAuth := resp.StatusCode == http.StatusProxyAuthRequired ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Basic") ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Digest")

	return requiresAuth, fmt.Sprintf("Proxy Status: %d", resp.StatusCode), nil
}

// BruteForce attempts to brute force proxy credentials
func (p *ProxyAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := p.ReadServiceWordlist("proxy")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"admin:admin",
			"admin:password",
			"admin:123456",
			"proxy:proxy",
			"proxy:password",
			"root:root",
			"root:password",
		}
	}

	// Create HTTP client with proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", p.Host, p.Port))
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
			Timeout: p.Timeout,
		}

		// Try to connect through proxy
		resp, err := client.Get("http://example.com")
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
		output, err := p.RunNmapScript(p.Host, p.Port, "http-proxy-brute")
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
