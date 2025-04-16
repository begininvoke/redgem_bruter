package services

// Service represents a network service with its default ports and protocols
type Service struct {
	Name        string
	Ports       []int
	Protocol    string
	Description string
}

// GetAllServices returns a map of all supported services
func GetAllServices() map[string]Service {
	return map[string]Service{
		"afp": {
			Name:        "AFP",
			Ports:       []int{548},
			Protocol:    "tcp",
			Description: "Apple Filing Protocol",
		},
		"db2": {
			Name:        "DB2",
			Ports:       []int{50000},
			Protocol:    "tcp",
			Description: "IBM DB2 Database",
		},
		"ftp": {
			Name:        "FTP",
			Ports:       []int{21},
			Protocol:    "tcp",
			Description: "File Transfer Protocol",
		},
		"http": {
			Name:        "HTTP",
			Ports:       []int{80},
			Protocol:    "tcp",
			Description: "Hypertext Transfer Protocol",
		},
		"https": {
			Name:        "HTTPS",
			Ports:       []int{443},
			Protocol:    "tcp",
			Description: "HTTP Secure",
		},
		"ldap": {
			Name:        "LDAP",
			Ports:       []int{389, 636},
			Protocol:    "tcp",
			Description: "Lightweight Directory Access Protocol",
		},
		"mssql": {
			Name:        "MSSQL",
			Ports:       []int{1433},
			Protocol:    "tcp",
			Description: "Microsoft SQL Server",
		},
		"mysql": {
			Name:        "MySQL",
			Ports:       []int{3306},
			Protocol:    "tcp",
			Description: "MySQL Database",
		},
		"pop3": {
			Name:        "POP3",
			Ports:       []int{110, 995},
			Protocol:    "tcp",
			Description: "Post Office Protocol 3",
		},
		"postgres": {
			Name:        "Postgres",
			Ports:       []int{5432},
			Protocol:    "tcp",
			Description: "PostgreSQL Database",
		},
		"redis": {
			Name:        "Redis",
			Ports:       []int{6379},
			Protocol:    "tcp",
			Description: "Redis Database",
		},
		"smb": {
			Name:        "SMB",
			Ports:       []int{445, 139},
			Protocol:    "tcp",
			Description: "Server Message Block",
		},
		"snmp": {
			Name:        "SNMP",
			Ports:       []int{161, 162},
			Protocol:    "udp",
			Description: "Simple Network Management Protocol",
		},
		"ssh": {
			Name:        "SSH",
			Ports:       []int{22},
			Protocol:    "tcp",
			Description: "Secure Shell",
		},
		"telnet": {
			Name:        "Telnet",
			Ports:       []int{23},
			Protocol:    "tcp",
			Description: "Telnet Protocol",
		},
		"kerberos": {
			Name:        "Kerberos",
			Ports:       []int{88},
			Protocol:    "tcp",
			Description: "Kerberos Authentication",
		},
		"vnc": {
			Name:        "VNC",
			Ports:       []int{5900, 5901, 5902},
			Protocol:    "tcp",
			Description: "Virtual Network Computing",
		},
		"winrm": {
			Name:        "WinRM",
			Ports:       []int{5985, 5986},
			Protocol:    "tcp",
			Description: "Windows Remote Management",
		},
		"teamcity": {
			Name:        "TeamCity",
			Ports:       []int{8111},
			Protocol:    "tcp",
			Description: "JetBrains TeamCity",
		},
		"mongodb": {
			Name:        "MongoDB",
			Ports:       []int{27017},
			Protocol:    "tcp",
			Description: "MongoDB Database",
		},
		"couchdb": {
			Name:        "CouchDB",
			Ports:       []int{5984},
			Protocol:    "tcp",
			Description: "Apache CouchDB",
		},
		"elasticsearch": {
			Name:        "Elasticsearch",
			Ports:       []int{9200},
			Protocol:    "tcp",
			Description: "Elasticsearch Search Engine",
		},
		"memcached": {
			Name:        "Memcached",
			Ports:       []int{11211},
			Protocol:    "tcp",
			Description: "Memcached Cache",
		},
		"rabbitmq": {
			Name:        "RabbitMQ",
			Ports:       []int{5672, 15672},
			Protocol:    "tcp",
			Description: "RabbitMQ Message Broker",
		},
		"mqtt": {
			Name:        "MQTT",
			Ports:       []int{1883, 8883},
			Protocol:    "tcp",
			Description: "Message Queuing Telemetry Transport",
		},
		"nats": {
			Name:        "NATS",
			Ports:       []int{4222},
			Protocol:    "tcp",
			Description: "NATS Messaging System",
		},
		"docker": {
			Name:        "Docker API",
			Ports:       []int{2375, 2376},
			Protocol:    "tcp",
			Description: "Docker API",
		},
		"jenkins": {
			Name:        "Jenkins",
			Ports:       []int{8080},
			Protocol:    "tcp",
			Description: "Jenkins CI/CD",
		},
		"grafana": {
			Name:        "Grafana",
			Ports:       []int{3000},
			Protocol:    "tcp",
			Description: "Grafana Monitoring",
		},
		"kibana": {
			Name:        "Kibana",
			Ports:       []int{5601},
			Protocol:    "tcp",
			Description: "Kibana Dashboard",
		},
		"netdata": {
			Name:        "Netdata",
			Ports:       []int{19999},
			Protocol:    "tcp",
			Description: "Netdata Monitoring",
		},
	}
}
