# RedGem Bruter

A service detection and brute force checking tool written in Go. This tool helps identify open services and check for authentication requirements on target systems.

## Features

- Service detection on common ports
- IP address resolution and display
- Service-specific actions for each supported service
- Nmap script integration for service identification
- Authentication detection for common services
- Support for multiple output formats (text, JSON, CSV)
- Configurable port scanning
- Wordlist support for brute force attempts
- Comprehensive service list with default ports

## Installation

```bash
go get github.com/yourusername/redgem_bruter
```

## Requirements

- Go 1.23.0 or higher
- Nmap (for advanced service detection)

## Usage

```bash
redgem_bruter -target <host> [-port <ports>] [-o <output_file>] [-f <format>] [-a]
```

### Flags

- `-target`: Target host to scan (required)
- `-port`: Comma-separated list of ports to scan (optional)
- `-o`: Output file for results (optional)
- `-f`: Output format (text, json, or csv) (default: text)
- `-a`: Enable brute force attack mode (optional)

### Examples

1. Scan all default ports on a host:
```bash
redgem_bruter -target example.com
```

2. Scan specific ports:
```bash
redgem_bruter -target example.com -port 80,443,8080
```

3. Save results to a file in JSON format:
```bash
redgem_bruter -target example.com -o results.json -f json
```

4. Enable brute force attack mode:
```bash
redgem_bruter -target example.com -a
```

## Supported Services

The tool supports scanning for the following services:

- AFP (Apple Filing Protocol) - Port 548
- DB2 (IBM DB2 Database) - Port 50000
- FTP (File Transfer Protocol) - Port 21
- HTTP (Hypertext Transfer Protocol) - Port 80
- HTTPS (HTTP Secure) - Port 443
- LDAP (Lightweight Directory Access Protocol) - Ports 389, 636
- MSSQL (Microsoft SQL Server) - Port 1433
- MySQL (MySQL Database) - Port 3306
- POP3 (Post Office Protocol 3) - Ports 110, 995
- PostgreSQL (PostgreSQL Database) - Port 5432
- Redis (Redis Database) - Port 6379
- SMB (Server Message Block) - Ports 445, 139
- SNMP (Simple Network Management Protocol) - Ports 161, 162 (UDP)
- SSH (Secure Shell) - Port 22
- Telnet (Telnet Protocol) - Port 23
- Kerberos (Kerberos Authentication) - Port 88
- VNC (Virtual Network Computing) - Ports 5900-5902
- WinRM (Windows Remote Management) - Ports 5985, 5986
- TeamCity (JetBrains TeamCity) - Port 8111
- MongoDB (MongoDB Database) - Port 27017
- CouchDB (Apache CouchDB) - Port 5984
- Elasticsearch (Elasticsearch Search Engine) - Port 9200
- Memcached (Memcached Cache) - Port 11211
- RabbitMQ (RabbitMQ Message Broker) - Ports 5672, 15672
- MQTT (Message Queuing Telemetry Transport) - Ports 1883, 8883
- NATS (NATS Messaging System) - Port 4222
- Docker API (Docker API) - Ports 2375, 2376
- Jenkins (Jenkins CI/CD) - Port 8080
- Grafana (Grafana Monitoring) - Port 3000
- Kibana (Kibana Dashboard) - Port 5601
- Netdata (Netdata Monitoring) - Port 19999
- Squid (Squid Proxy Server) - Port 3128

## Service-Specific Actions

Each service has its own specific action implementation:

### MongoDB
- Uses `mongodb-info` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### Redis
- Uses `redis-info` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### Elasticsearch
- Uses `http-elasticsearch-header` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### HTTP/HTTPS
- Uses `http-auth-finder` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### SSH
- Uses `ssh-auth-methods` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### MySQL
- Uses `mysql-info` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### PostgreSQL
- Uses `pgsql-brute` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### LDAP
- Uses `ldap-brute` Nmap script
- Checks for authentication requirements
- Supports brute force attempts

### Squid Proxy
- Uses `http-proxy-brute` Nmap script
- Checks for authentication requirements
- Supports multiple authentication methods (Basic, Digest, NTLM)
- Detects Squid-specific headers and error messages
- Supports brute force attempts with common proxy credentials
- Default port: 3128

## Output Formats

1. Text (default):
```
IP: 192.168.1.1, Service: http, Port: 80, Protocol: tcp, Open: true, Auth: false, Info: [Nmap scan results]
```

2. JSON:
```json
{
    "ip": "192.168.1.1",
    "service": "http",
    "port": 80,
    "protocol": "tcp",
    "open": true,
    "auth": false,
    "info": "[Nmap scan results]"
}
```

3. CSV:
```
IP,Service,Port,Protocol,Open,Auth,Vulnerable,VulnDescription,DefaultCreds,DefaultUser,DefaultPass,GuestAccess,Version,Banner,Info,LastChecked
192.168.1.1,http,80,tcp,true,false,false,,false,,,,,,,[Nmap scan results]
```

## Project Structure

```
.
├── cmd/            # Command-line interface
├── pkg/            # Core packages
├── wordlists/      # Default wordlists
├── go.mod          # Go module file
├── go.sum          # Go module checksums
└── README.md       # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.