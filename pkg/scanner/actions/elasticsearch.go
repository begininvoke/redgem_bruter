package actions

import (
	"strings"
)

// ElasticsearchAction implements Elasticsearch-specific actions
type ElasticsearchAction struct {
	*BaseAction
}

// NewElasticsearchAction creates a new Elasticsearch action
func NewElasticsearchAction() *ElasticsearchAction {
	return &ElasticsearchAction{
		BaseAction: NewBaseAction(),
	}
}

// CheckAuth checks if Elasticsearch requires authentication
func (e *ElasticsearchAction) CheckAuth(host string, port int) (bool, string, error) {
	// First check if port is open
	open, err := e.CheckPort(host, port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Elasticsearch header script
	output, err := e.RunNmapScript(host, port, "http-elasticsearch-header")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "auth") ||
		strings.Contains(output, "login") ||
		strings.Contains(output, "password") ||
		strings.Contains(output, "401") ||
		strings.Contains(output, "403")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Elasticsearch
func (e *ElasticsearchAction) BruteForce(host string, port int, wordlist string) (bool, string, error) {
	// Implementation for Elasticsearch brute force
	return false, "Brute force not implemented for Elasticsearch", nil
}
