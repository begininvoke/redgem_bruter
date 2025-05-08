package actions

import (
	"strings"
)

// RabbitMQAction implements RabbitMQ service scanning
type RabbitMQAction struct {
	BaseAction
}

// NewRabbitMQAction creates a new RabbitMQ action
func NewRabbitMQAction() *RabbitMQAction {
	return &RabbitMQAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if RabbitMQ requires authentication
func (r *RabbitMQAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := r.CheckPort(r.Host, r.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run RabbitMQ auth script
	output, err := r.RunNmapScript(r.Host, r.Port, "amqp-info")
	if err != nil {
		return false, "", err
	}

	// RabbitMQ typically requires authentication
	return true, output, nil
}

// BruteForce attempts to brute force RabbitMQ credentials
func (r *RabbitMQAction) BruteForce() (bool, string, error) {
	// Run RabbitMQ brute force script
	output, err := r.RunNmapScript(r.Host, r.Port, "amqp-brute")
	if err != nil {
		return false, "", err
	}

	// Check if brute force was successful
	success := strings.Contains(output, "Valid credentials") ||
		strings.Contains(output, "Login successful")

	return success, output, nil
}
