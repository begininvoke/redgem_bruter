package actions

// GetServiceAction returns the appropriate service action for the given service
func GetServiceAction(service string) ServiceAction {
	switch service {
	case "mongodb":
		return NewMongoDBAction()
	case "redis":
		return NewRedisAction()
	case "elasticsearch":
		return NewElasticsearchAction()
	case "http", "https":
		return NewHTTPAction()
	case "ssh":
		return NewSSHAction()
	case "mysql":
		return NewMySQLAction()
	case "postgres":
		return NewPostgresAction()
	default:
		// Default action for unknown services
		return NewBaseAction()
	}
}
