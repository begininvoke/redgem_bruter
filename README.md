# RedGem Bruter

A powerful and comprehensive service detection and authentication testing tool written in Go. This tool helps security professionals and system administrators identify open services, check authentication requirements, and test for common vulnerabilities across a wide range of network services.

## Key Features

### Service Detection
- Comprehensive service detection across 30+ common network services
- Intelligent port scanning with service fingerprinting
- Nmap script integration for advanced service identification
- Support for both TCP and UDP services
- Automatic service version detection

### Authentication Testing
- Authentication requirement detection for all supported services
- Support for multiple authentication methods:
  - Basic/Digest HTTP authentication
  - NTLM authentication
  - Database authentication
  - SSH key-based authentication
  - Proxy authentication
  - Custom authentication schemes

### Brute Force Capabilities
- Service-specific brute force attempts
- Comprehensive wordlists for each service type
- Support for common credential patterns
- Customizable brute force strategies
- Rate limiting and timeout controls

### Supported Services
The tool supports a wide range of services including:

#### Database Services
- MySQL (Port 3306)
- PostgreSQL (Port 5432)
- MongoDB (Port 27017)
- MSSQL (Port 1433)
- Redis (Port 6379)
- CouchDB (Port 5984)
- DB2 (Port 50000)

#### Web Services
- HTTP/HTTPS (Ports 80/443)
- Jenkins (Port 8080)
- Kibana (Port 5601)
- Grafana (Port 3000)
- Netdata (Port 19999)
- TeamCity (Port 8111)

#### Messaging & Queue Services
- RabbitMQ (Ports 5672, 15672)
- MQTT (Ports 1883, 8883)
- NATS (Port 4222)

#### Remote Access Services
- SSH (Port 22)
- RDP (Port 3389)
- VNC (Ports 5900-5902)
- WinRM (Ports 5985, 5986)
- Telnet (Port 23)

#### File & Storage Services
- FTP (Port 21)
- SMB (Ports 445, 139)
- AFP (Port 548)

#### Proxy & Security Services
- Squid Proxy (Port 3128)
- LDAP (Ports 389, 636)
- Kerberos (Port 88)

#### Monitoring & Management
- SNMP (Ports 161, 162)
- Docker API (Ports 2375, 2376)

### Output Formats
- Text output for human readability
- JSON output for programmatic processing
- CSV output for spreadsheet analysis
- Detailed service information including:
  - Authentication status
  - Service version
  - Banner information
  - Vulnerability indicators
  - Default credentials status

### Security Features
- Rate limiting to prevent service disruption
- Configurable timeouts
- Safe brute force attempts
- Error handling and logging
- Support for proxy connections

## Use Cases

1. **Security Auditing**
   - Identify open services
   - Check for default credentials
   - Test authentication requirements
   - Detect common vulnerabilities

2. **System Administration**
   - Service discovery
   - Configuration verification
   - Access control testing
   - Security posture assessment

3. **Penetration Testing**
   - Initial reconnaissance
   - Service enumeration
   - Authentication testing
   - Vulnerability assessment

4. **Compliance Checking**
   - Security policy verification
   - Access control validation
   - Service configuration auditing
   - Default credential detection

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

## Project Structure

```
.
├── cmd/            # Command-line interface
├── pkg/            # Core packages
│   ├── scanner/    # Scanning functionality
│   │   ├── actions/    # Service-specific actions
│   │   └── wordlists/  # Brute force wordlists
│   └── services/   # Service definitions
├── wordlists/      # Default wordlists
├── go.mod          # Go module file
├── go.sum          # Go module checksums
└── README.md       # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. We're particularly interested in:

- New service support
- Improved detection methods
- Additional wordlists
- Bug fixes and improvements
- Documentation updates

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is designed for legitimate security testing and system administration purposes only. Always ensure you have proper authorization before testing any system. The authors are not responsible for any misuse or damage caused by this tool.