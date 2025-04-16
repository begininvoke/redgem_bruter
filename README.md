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

- Go 1.16 or higher
- Nmap (for advanced service detection)

## Usage

```bash
redgem_bruter -target <host> [-port <ports>] [-o <output_file>] [-f <format>] [-w <wordlist>]
```

### Flags

- `-target`: Target host to scan (required)
- `-port`: Comma-separated list of ports to scan (optional)
- `-o`: Output file for results (optional)
- `-f`: Output format (text, json, or csv) (default: text)
- `-w`: Wordlist file for brute force attempts (optional)

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

4. Use a wordlist for brute force attempts:
```bash
redgem_bruter -target example.com -w wordlist.txt
```

## Supported Services

The tool supports scanning for various services including:

- HTTP/HTTPS
- FTP
- SSH
- MySQL
- PostgreSQL
- MongoDB
- Redis
- Elasticsearch
- And many more...

For a complete list of supported services and their default ports, see the services package.

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

## Output Formats

1. Text (default):
```
IP: 192.168.1.1, Service: http, Port: 80, Protocol: tcp, Open: true, Auth: false, Info: [Nmap scan results]
```

2. JSON:
```json
{"ip":"192.168.1.1","service":"http","port":80,"protocol":"tcp","open":true,"auth":false,"info":"[Nmap scan results]"}
```

3. CSV:
```
192.168.1.1,http,80,tcp,true,false,[Nmap scan results]
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.