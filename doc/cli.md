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
| `--version` | Display version information |
| `--help` | Show help information |

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
| `-q, --quiet` | Suppress console output | false |
| `--status-reporter` | Status logging | true |
| `--auto-reload` | Enable config hot reload | false |

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
| `--pipelines.N.plugin_sources.N.type` | Source type |
| `--pipelines.N.flow.filters.N.type` | Filter type |
| `--pipelines.N.plugin_sinks.N.type` | Sink type |

## Flag Formats

### Boolean Flags

```bash
logwisp --quiet
logwisp --quiet=true
logwisp --pipelines.0.plugin_sources.0.type=console
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
logwisp --pipelines.0.sources.0.type=console
```

### Array Values (JSON)

```bash
logwisp --pipelines.0.flow.filters.0.patterns='["ERROR","WARN"]'
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
logwisp --pipelines.0.plugin_sources.0.type=console --pipelines.0.plugin_sinks.0.type=console
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

## Help System

### General Help

```bash
logwisp --help
logwisp -h
logwisp help
```

## Special Flags

### Internal Flags

These flags are for internal use:
- `--background-daemon`: Child process indicator
- `--config-save-on-exit`: Save config on shutdown

### Hidden Behaviors

- SIGHUP ignored ignored during startup (after startup triggers config reload)
- Automatic panic recovery in pipelines
- Resource cleanup on shutdown
