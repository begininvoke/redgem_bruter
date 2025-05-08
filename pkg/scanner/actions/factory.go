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
	case "ftp":
		return NewFTPAction()
	case "telnet":
		return NewTelnetAction()
	case "smtp":
		return NewSMTPAction()
	case "ldap":
		return NewLDAPAction()
	case "rdp":
		return NewRDPAction()
	case "afp":
		return NewAFPAction()
	case "db2":
		return NewDB2Action()
	case "pop3":
		return NewPOP3Action()
	case "mssql":
		return NewMSSQLAction()
	case "smb":
		return NewSMBAction()
	case "snmp":
		return NewSNMPAction()
	case "kerberos":
		return NewKerberosAction()
	case "vnc":
		return NewVNCAction()
	case "winrm":
		return NewWinRMAction()
	case "teamcity":
		return NewTeamCityAction()
	case "couchdb":
		return NewCouchDBAction()
	case "memcached":
		return NewMemcachedAction()
	case "rabbitmq":
		return NewRabbitMQAction()
	case "mqtt":
		return NewMQTTAction()
	case "nats":
		return NewNATSAction()
	case "docker":
		return NewDockerAction()
	case "jenkins":
		return NewJenkinsAction()
	case "grafana":
		return NewGrafanaAction()
	case "kibana":
		return NewKibanaAction()
	case "netdata":
		return NewNetdataAction()
	default:
		// Default action for unknown services
		return NewBaseAction()
	}
}
