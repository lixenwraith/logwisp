# Command Line Interface

LogWisp CLI reference for commands and options.

## Synopsis

```bash
logwisp [command] [options]
logwisp [options]
```

## Commands

### Main Commands

| Command | Description |
|---------|-------------|
| `auth` | Generate authentication credentials |
| `tls` | Generate TLS certificates |
| `version` | Display version information |
| `help` | Show help information |

### auth Command

Generate authentication credentials.

```bash
logwisp auth [options]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --user` | Username | Required for password auth |
| `-p, --password` | Password | Prompts if not provided |
| `-b, --basic` | Generate basic auth | - |
| `-s, --scram` | Generate SCRAM auth | - |
| `-k, --token` | Generate bearer token | - |
| `-l, --length` | Token length in bytes | 32 |

### tls Command

Generate TLS certificates.

```bash
logwisp tls [options]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `-ca` | Generate CA certificate | - |
| `-server` | Generate server certificate | - |
| `-client` | Generate client certificate | - |
| `-host` | Comma-separated hosts/IPs | localhost |
| `-o` | Output file prefix | Required |
| `-ca-cert` | CA certificate file | Required for server/client |
| `-ca-key` | CA key file | Required for server/client |
| `-days` | Certificate validity days | 365 |

### version Command

Display version information.

```bash
logwisp version
logwisp -v
logwisp --version
```

Output includes:
- Version number
- Build date
- Git commit hash
- Go version

## Global Options

### Configuration Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Configuration file path | `./logwisp.toml` |
| `-b, --background` | Run as daemon | false |
| `-q, --quiet` | Suppress console output | false |
| `--disable-status-reporter` | Disable status logging | false |
| `--config-auto-reload` | Enable config hot reload | false |

### Logging Options

| Flag | Description | Values |
|------|-------------|--------|
| `--logging.output` | Log output mode | file, stdout, stderr, split, all, none |
| `--logging.level` | Log level | debug, info, warn, error |
| `--logging.file.directory` | Log directory | Path |
| `--logging.file.name` | Log filename | String |
| `--logging.file.max_size_mb` | Max file size | Integer |
| `--logging.file.max_total_size_mb` | Total size limit | Integer |
| `--logging.file.retention_hours` | Retention period | Float |
| `--logging.console.target` | Console target | stdout, stderr, split |
| `--logging.console.format` | Output format | txt, json |

### Pipeline Options

Configure pipelines via CLI (N = array index, 0-based).

**Pipeline Configuration:**

| Flag | Description |
|------|-------------|
| `--pipelines.N.name` | Pipeline name |
| `--pipelines.N.sources.N.type` | Source type |
| `--pipelines.N.filters.N.type` | Filter type |
| `--pipelines.N.sinks.N.type` | Sink type |

## Flag Formats

### Boolean Flags

```bash
logwisp --quiet
logwisp --quiet=true
logwisp --quiet=false
```

### String Flags

```bash
logwisp --config /etc/logwisp/config.toml
logwisp -c config.toml
```

### Nested Configuration

```bash
logwisp --logging.level=debug
logwisp --pipelines.0.name=myapp
logwisp --pipelines.0.sources.0.type=stdin
```

### Array Values (JSON)

```bash
logwisp --pipelines.0.filters.0.patterns='["ERROR","WARN"]'
```

## Environment Variables

All flags can be set via environment:

```bash
export LOGWISP_QUIET=true
export LOGWISP_LOGGING_LEVEL=debug
export LOGWISP_PIPELINES_0_NAME=myapp
```

## Configuration Precedence

1. Command-line flags (highest)
2. Environment variables
3. Configuration file
4. Built-in defaults (lowest)

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration file not found |
| 137 | SIGKILL received |

## Signal Handling

| Signal | Action |
|--------|--------|
| SIGINT (Ctrl+C) | Graceful shutdown |
| SIGTERM | Graceful shutdown |
| SIGHUP | Reload configuration |
| SIGUSR1 | Reload configuration |
| SIGKILL | Immediate termination |

## Usage Patterns

### Development Mode

```bash
# Verbose logging to console
logwisp --logging.output=stderr --logging.level=debug

# Quick test with stdin
logwisp --pipelines.0.sources.0.type=stdin --pipelines.0.sinks.0.type=console
```

### Production Deployment

```bash
# Background with file logging
logwisp --background --config /etc/logwisp/prod.toml --logging.output=file

# Systemd service
ExecStart=/usr/local/bin/logwisp --config /etc/logwisp/config.toml
```

### Debugging

```bash
# Check configuration
logwisp --config test.toml --logging.level=debug --disable-status-reporter

# Dry run (verify config only)
logwisp --config test.toml --quiet
```

### Quick Commands

```bash
# Generate admin password
logwisp auth -u admin -b

# Create self-signed certs
logwisp tls -server -host localhost -o server

# Check version
logwisp version
```

## Help System

### General Help

```bash
logwisp --help
logwisp -h
logwisp help
```

### Command Help

```bash
logwisp auth --help
logwisp tls --help
logwisp help auth
```

## Special Flags

### Internal Flags

These flags are for internal use:
- `--background-daemon`: Child process indicator
- `--config-save-on-exit`: Save config on shutdown

### Hidden Behaviors

- SIGHUP ignored by default (nohup behavior)
- Automatic panic recovery in pipelines
- Resource cleanup on shutdown