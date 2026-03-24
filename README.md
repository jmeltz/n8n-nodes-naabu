# n8n-nodes-naabu

An [n8n](https://n8n.io/) community node for port scanning with [naabu](https://github.com/projectdiscovery/naabu).

Naabu is a fast port scanner written in Go by ProjectDiscovery. This node wraps the naabu CLI so you can run port scans directly from your n8n workflows.

## Prerequisites

Naabu must be installed and available in the system PATH where n8n is running.

```bash
# Install with Go
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Or with Homebrew
brew install naabu
```

## Installation

In your n8n instance:

```bash
npm install n8n-nodes-naabu
```

Or install via the n8n community nodes UI: **Settings > Community Nodes > Install > `n8n-nodes-naabu`**

## Node Parameters

### Target

Host(s) to scan. Supports single hosts, IPs, or comma-separated lists.

### Port Selection

| Mode | Description |
|------|-------------|
| **Top Ports** | Scan top 100 or 1000 most common ports |
| **Specific Ports** | Define exact ports or ranges (e.g. `80,443,8080-8090`) |
| **Full Scan** | Scan all 65535 ports |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| Scan Type | CONNECT | `CONNECT` (default) or `SYN` (requires root) |
| Rate | 1000 | Packets per second |
| Threads | 25 | Number of worker threads |
| Retries | 3 | Number of retries per port |
| Timeout | 1000 | Timeout in milliseconds per port |
| Exclude Ports | — | Ports to skip (comma-separated) |
| Exclude Hosts | — | Hosts to skip (comma-separated) |
| Exclude CDN | false | Skip full scan for CDN/WAF hosts (only scan 80, 443) |
| Display CDN | false | Include CDN provider info in results |
| Nmap Command | — | Run nmap on discovered ports (e.g. `nmap -sV -Pn`) |

## Output

Each open port is returned as a separate item:

```json
{ "host": "example.com", "ip": "93.184.216.34", "port": 443 }
```

When no open ports are found, a single item is returned:

```json
{ "target": "example.com", "openPorts": [], "count": 0 }
```

## Example Workflow

1. **Manual Trigger** or **Schedule** node
2. **Set** node with target hostname
3. **Naabu** node configured with desired scan options
4. **IF** node to filter results
5. **Slack/Email** node to alert on open ports

## Development

```bash
git clone https://github.com/jmeltz/n8n-nodes-naabu.git
cd n8n-nodes-naabu
npm install --ignore-scripts
npm run build
```

## License

[MIT](LICENSE)
