package actions

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Port8080Action implements service detection and routing for port 8080
type Port8080Action struct {
	BaseAction
}

// NewPort8080Action creates a new port 8080 action
func NewPort8080Action() *Port8080Action {
	return &Port8080Action{
		BaseAction: *NewBaseAction(),
	}
}

// DetectService detects whether the service is Jenkins or HTTP proxy
func (p *Port8080Action) DetectService() (string, error) {
	// First check if port is open
	open, err := p.CheckPort(p.Host, p.Port)
	if err != nil {
		return "", err
	}
	if !open {
		return "", fmt.Errorf("port closed")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: p.Timeout,
	}

	// Try to access Jenkins-specific endpoints
	jenkinsEndpoints := []string{
		"/",
		"/login",
		"/api/json",
		"/manage",
	}

	for _, endpoint := range jenkinsEndpoints {
		url := fmt.Sprintf("http://%s:%d%s", p.Host, p.Port, endpoint)
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for Jenkins indicators
		if resp.StatusCode == http.StatusOK {
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "text/html") {
				// Check response body for Jenkins indicators
				if strings.Contains(resp.Header.Get("Set-Cookie"), "JSESSIONID") ||
					strings.Contains(resp.Header.Get("Set-Cookie"), "jenkins") {
					return "jenkins", nil
				}
			}
		}
	}

	// Try to detect HTTP proxy
	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", p.Host, p.Port))
	if err != nil {
		return "", err
	}

	client.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	req, err := http.NewRequest("GET", "http://speedtest.llsapi.com", nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Proxy-Connection", "Keep-Alive")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check for proxy indicators
	if resp.StatusCode == http.StatusProxyAuthRequired ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Basic") ||
		strings.Contains(resp.Header.Get("Proxy-Authenticate"), "Digest") {
		return "proxy", nil
	}

	// If we can't definitively determine the service type, return unknown
	return "unknown", nil
}

// CheckAuth checks if the service requires authentication
func (p *Port8080Action) CheckAuth() (bool, string, error) {
	// Detect service type
	serviceType, err := p.DetectService()
	if err != nil {
		return false, "", err
	}

	// Route to appropriate action based on service type
	switch serviceType {
	case "jenkins":
		jenkins := NewJenkinsAction()
		jenkins.Host = p.Host
		jenkins.Port = p.Port
		jenkins.Timeout = p.Timeout
		requiresAuth, info, _, err := jenkins.CheckAuth()
		return requiresAuth, info, err

	case "proxy":
		proxy := NewProxyAction()
		proxy.Host = p.Host
		proxy.Port = p.Port
		proxy.Timeout = p.Timeout
		return proxy.CheckAuth()

	default:
		return false, "Unknown service type", nil
	}
}

// BruteForce attempts to brute force the service credentials
func (p *Port8080Action) BruteForce() (bool, string, error) {
	// Detect service type
	serviceType, err := p.DetectService()
	if err != nil {
		return false, "", err
	}

	// Route to appropriate action based on service type
	switch serviceType {
	case "jenkins":
		jenkins := NewJenkinsAction()
		jenkins.Host = p.Host
		jenkins.Port = p.Port
		jenkins.Timeout = p.Timeout
		return jenkins.BruteForce()

	case "proxy":
		proxy := NewProxyAction()
		proxy.Host = p.Host
		proxy.Port = p.Port
		proxy.Timeout = p.Timeout
		return proxy.BruteForce()

	default:
		return false, "Unknown service type", nil
	}
}
