package actions

import (
	"fmt"
	"strings"
)

// RedisAction implements Redis service scanning
type RedisAction struct {
	BaseAction
}

// NewRedisAction creates a new Redis action
func NewRedisAction() *RedisAction {
	return &RedisAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Redis requires authentication and potential vulnerabilities
func (r *RedisAction) CheckAuth() (bool, string, bool, error) {
	// First check if port is open
	open, err := r.CheckPort(r.Host, r.Port)
	if err != nil {
		return false, "", false, err
	}
	if !open {
		return false, "Port closed", false, nil
	}

	// Get banner to check version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", false, err
	}

	// Check for known vulnerable versions
	vulnerable := false
	if strings.Contains(version, "2.8") || strings.Contains(version, "3.0") {
		vulnerable = true
	}

	// Run Redis-specific auth detection
	output, err := r.RunNmapScript(r.Host, r.Port, "redis-info")
	if err != nil {
		return false, "", false, err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "NOAUTH") ||
		strings.Contains(output, "WRONGPASS")

	return requiresAuth, fmt.Sprintf("Redis %s - %s", version, output), vulnerable, nil
}

// CheckVulnerability checks for Redis-specific vulnerabilities
func (r *RedisAction) CheckVulnerability() (bool, string, error) {
	// Get version
	_, version, err := r.GetBanner()
	if err != nil {
		return false, "", err
	}

	vulnerabilities := []string{}

	// Check for known vulnerable versions
	if strings.Contains(version, "2.8") || strings.Contains(version, "3.0") {
		vulnerabilities = append(vulnerabilities, "Known vulnerable version")
	}

	// Check for anonymous access
	output, err := r.RunNmapScript(r.Host, r.Port, "redis-brute")
	if err == nil && strings.Contains(output, "Anonymous access") {
		vulnerabilities = append(vulnerabilities, "Anonymous access allowed")
	}

	// Check for default credentials
	output, err = r.RunNmapScript(r.Host, r.Port, "redis-brute")
	if err == nil && strings.Contains(output, "Valid credentials") {
		vulnerabilities = append(vulnerabilities, "Default credentials found")
	}

	if len(vulnerabilities) > 0 {
		return true, fmt.Sprintf("Vulnerabilities found: %s", strings.Join(vulnerabilities, ", ")), nil
	}

	return false, "No obvious vulnerabilities detected", nil
}

// BruteForce attempts to brute force Redis credentials
func (r *RedisAction) BruteForce() (bool, string, error) {
	// Run Redis brute force script
	output, err := r.RunNmapScript(r.Host, r.Port, "redis-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
