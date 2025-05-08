package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"
)

// RedisAction implements Redis-specific actions
type RedisAction struct {
	BaseAction
}

// NewRedisAction creates a new Redis action
func NewRedisAction() *RedisAction {
	return &RedisAction{
		BaseAction: *NewBaseAction(),
	}
}

// CheckAuth checks if Redis requires authentication
func (r *RedisAction) CheckAuth() (bool, string, error) {
	// First check if port is open
	open, err := r.CheckPort(r.Host, r.Port)
	if err != nil {
		return false, "", err
	}
	if !open {
		return false, "Port closed", nil
	}

	// Run Redis auth script
	output, err := r.RunNmapScript(r.Host, r.Port, "redis-info")
	if err != nil {
		return false, "", err
	}

	// Check if authentication is required
	requiresAuth := strings.Contains(output, "authentication required") ||
		strings.Contains(output, "NOAUTH") ||
		strings.Contains(output, "WRONGPASS")

	return requiresAuth, output, nil
}

// BruteForce attempts to brute force Redis
func (r *RedisAction) BruteForce() (bool, string, error) {
	// Try to read from service-specific wordlist first
	credentials, err := r.ReadServiceWordlist("redis")
	if err != nil {
		// Fall back to default credentials if wordlist is not available
		credentials = []string{
			"default:",
			"default:redis",
			"default:password",
			"default:123456",
			"redis:redis",
			"redis:password",
			"redis:123456",
		}
	}

	var success bool
	var successInfo string

	for _, cred := range credentials {
		parts := strings.Split(cred, ":")
		if len(parts) != 2 {
			continue
		}

		username, password := parts[0], parts[1]

		client := redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", r.Host, r.Port),
			Password:     password,
			Username:     username,
			DialTimeout:  r.Timeout,
			ReadTimeout:  r.Timeout,
			WriteTimeout: r.Timeout,
		})

		// Try to ping the server
		ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
		err := client.Ping(ctx).Err()
		cancel()

		if err == nil {
			client.Close()
			success = true
			successInfo = fmt.Sprintf("Successfully authenticated with username: %s, password: %s", username, password)
			break
		}
		client.Close()
	}

	if !success {
		return false, "Failed to brute force Redis with common credentials", nil
	}

	return true, successInfo, nil
}
