# Installation Guide

This guide provides detailed instructions for setting up PentestAgent and its MCP server dependencies.

## Table of Contents

- [Requirements](#requirements)
- [Quick Install](#quick-install)
- [Development Install](#development-install)
- [MCP Server Setup](#mcp-server-setup)
- [Configuration](#configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Requirements

### System Requirements

- **Python**: 3.10 or higher
- **Node.js**: 18+ (for npx-based MCP servers)
- **Docker**: 20.10+ (recommended for containerized servers)
- **Git**: 2.0+
- **OS**: Linux, macOS, or Windows (WSL2 recommended)

### Optional Requirements

- **Java 11+**: For Burp Suite MCP
- **Metasploit Framework**: For exploitation features
- **uv**: Fast Python package manager (recommended)

## Quick Install

```bash
# Clone the repository
git clone https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install PentestAgent
pip install -e .

# Verify installation
python -m src.cli.cli --help
```

## Development Install

```bash
# Clone with submodules (includes external MCP servers)
git clone --recurse-submodules https://github.com/cawa102/VibeHackAI.git
cd VibeHackAI

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Run tests to verify
pytest
```

## MCP Server Setup

PentestAgent integrates with multiple MCP servers. Below are setup instructions for each.

### Core MCP Servers

#### 1. Filesystem MCP (Required)

```bash
# Install via npx (runs on demand)
npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

#### 2. Nmap MCP (Recommended)

```bash
# Install nmap first
# macOS:
brew install nmap

# Ubuntu/Debian:
sudo apt-get install nmap

# Install MCP server
npx -y mcp-nmap-server
```

### OSINT MCP Servers

#### 3. Shodan MCP

Requires a [Shodan API key](https://account.shodan.io/).

```bash
# Set environment variable
export SHODAN_API_KEY="your_shodan_api_key"

# Install and run
npx -y @burtthecoder/mcp-shodan
```

#### 4. WhoisXML API MCP

Requires a [WhoisXML API key](https://whoisxmlapi.com/).

```bash
export WHOISXMLAPI_API_KEY="your_whoisxmlapi_key"
npx -y @whoisxmlapidotcom/mcp-whoisxmlapi
```

### Vulnerability Research MCP Servers

#### 5. CVE-Search MCP

```bash
# Clone the CVE-Search MCP
git clone https://github.com/example/cve-search-mcp external/cve-search-mcp
cd external/cve-search-mcp

# Install dependencies (using uv)
uv sync

# Run
uv run main.py
```

#### 6. Snyk MCP

Requires [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli) and API token.

```bash
# Install Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Or set token directly
export SNYK_TOKEN="your_snyk_token"
```

### Git Integration MCP Servers

#### 7. GitHub MCP

Requires a [GitHub Personal Access Token](https://github.com/settings/tokens).

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN="your_github_token"

# Run via Docker
docker run -i --rm \
  -e GITHUB_PERSONAL_ACCESS_TOKEN \
  ghcr.io/github/github-mcp-server
```

#### 8. GitLab MCP

```bash
npx -y mcp-remote https://gitlab.com/api/v4/mcp
```

### Security Testing MCP Servers

#### 9. Burp Suite MCP

Requires Burp Suite Professional and the MCP proxy extension.

```bash
# Download Burp MCP Proxy JAR
# Set path to JAR
export BURP_MCP_PROXY_JAR_PATH="/path/to/burp-mcp-proxy.jar"

# Start Burp Suite with MCP extension enabled
# Then start the proxy
java -jar ${BURP_MCP_PROXY_JAR_PATH} --sse-url http://127.0.0.1:9876
```

#### 10. Metasploit MCP

Requires Metasploit Framework with MSFRPC enabled.

```bash
# Start Metasploit RPC server
msfrpcd -P your_password -S -f

# Set environment variables
export MSF_PASSWORD="your_password"
export MSF_SERVER="127.0.0.1"
export MSF_PORT="55553"
export MSF_SSL="false"

# Run Metasploit MCP
python external/MetasploitMCP/MetasploitMCP.py --transport stdio
```

#### 11. Kali MCP

For Kali Linux tool integration.

```bash
# Install mcp-server
pip install mcp-server

# Run
mcp-server --server http://localhost:5000 --timeout 300
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Required API Keys
SHODAN_API_KEY=your_shodan_key
SNYK_TOKEN=your_snyk_token
GITHUB_PERSONAL_ACCESS_TOKEN=your_github_token
WHOISXMLAPI_API_KEY=your_whoisxmlapi_key

# Metasploit Configuration
MSF_PASSWORD=your_msf_password
MSF_SERVER=127.0.0.1
MSF_PORT=55553
MSF_SSL=false

# Burp Suite Configuration
BURP_MCP_PROXY_JAR_PATH=/path/to/burp-mcp-proxy.jar

# External MCP Directories
CVE_SEARCH_MCP_DIR=/path/to/cve-search-mcp
METASPLOIT_MCP_DIR=/path/to/MetasploitMCP
```

### MCP Configuration File

Edit `.mcp.json` to configure your MCP servers:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/your/workspace"]
    },
    "nmap": {
      "command": "npx",
      "args": ["-y", "mcp-nmap-server"]
    }
  }
}
```

### Settings File

Edit `settings.json` for runtime configuration:

```json
{
  "workspace_root": "/path/to/workspace",
  "session_timeout": 3600,
  "approval_timeout": 300,
  "max_consecutive_errors": 2
}
```

## Verification

### Check Installation

```bash
# Verify Python package
python -c "from src.orchestrator import Orchestrator; print('OK')"

# Run unit tests
pytest tests/ -v

# Check MCP connectivity
python -m src.cli.cli
> status
```

### Test MCP Servers

```bash
# Test filesystem MCP
echo '{"method": "list_directory", "params": {"path": "."}}' | \
  npx -y @modelcontextprotocol/server-filesystem .

# Test nmap MCP
echo '{"method": "scan", "params": {"target": "127.0.0.1"}}' | \
  npx -y mcp-nmap-server
```

## Troubleshooting

### Common Issues

#### "Module not found" error

```bash
# Ensure you're in the virtual environment
source venv/bin/activate

# Reinstall in editable mode
pip install -e .
```

#### MCP server connection failed

1. Check if the MCP server is running
2. Verify environment variables are set
3. Check firewall/network settings
4. Review logs in `workspace/logs/`

#### Permission denied (Nmap)

```bash
# On Linux, nmap may need sudo for certain scans
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)
```

#### Docker issues

```bash
# Ensure Docker is running
docker info

# Check container logs
docker logs <container_id>
```

### Getting Help

- Check the [docs/](docs/) directory for specifications
- Open an issue on GitHub
- Review existing issues for similar problems

## Next Steps

After installation:

1. Read the [README.md](README.md) for usage instructions
2. Review [SECURITY.md](SECURITY.md) for security guidelines
3. Check [examples/](examples/) for usage examples
4. Read the specifications in [docs/](docs/)
