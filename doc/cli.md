# Command Line Interface

LogWisp CLI options for controlling behavior without modifying configuration files.

## Synopsis

```bash
logwisp [options]
```

## General Options

### `--config <path>`
Configuration file location.
- **Default**: `~/.config/logwisp/logwisp.toml`
- **Example**: `logwisp --config /etc/logwisp/production.toml`

### `--router`
Enable HTTP router mode for path-based routing.
- **Default**: `false`
- **Example**: `logwisp --router`

### `--version`
Display version information.

### `--background`
Run as background process.
- **Example**: `logwisp --background`

### `--quiet`
Suppress all output (overrides logging configuration) except sinks.
- **Example**: `logwisp --quiet`

### `--disable-status-reporter`
Disable periodic status reporting.
- **Example**: `logwisp --disable-status-reporter`

### `--config-auto-reload`
Enable automatic configuration reloading on file changes.
- **Example**: `logwisp --config-auto-reload --config /etc/logwisp/config.toml`
- Monitors configuration file for changes
- Reloads pipelines without restart
- Preserves connections during reload

### `--config-save-on-exit`
Save current configuration to file on exit.
- **Example**: `logwisp --config-save-on-exit`
- Useful with runtime modifications
- Requires valid config file path

## Logging Options

Override configuration file settings:

### `--logging.output <mode>`
LogWisp's operational log output.
- **Values**: `file`, `stdout`, `stderr`, `both`, `none`
- **Example**: `logwisp --logging.output both`

### `--logging.level <level>`
Minimum log level.
- **Values**: `debug`, `info`, `warn`, `error`
- **Example**: `logwisp --logging.level debug`

### `--logging.file.directory <path>`
Log directory (with file output).
- **Example**: `logwisp --logging.file.directory /var/log/logwisp`

### `--logging.file.name <name>`
Log file name (with file output).
- **Example**: `logwisp --logging.file.name app`

### `--logging.file.max_size_mb <size>`
Maximum log file size in MB.
- **Example**: `logwisp --logging.file.max_size_mb 200`

### `--logging.file.max_total_size_mb <size>`
Maximum total log size in MB.
- **Example**: `logwisp --logging.file.max_total_size_mb 2000`

### `--logging.file.retention_hours <hours>`
Log retention period in hours.
- **Example**: `logwisp --logging.file.retention_hours 336`

### `--logging.console.target <target>`
Console output destination.
- **Values**: `stdout`, `stderr`, `split`
- **Example**: `logwisp --logging.console.target split`

### `--logging.console.format <format>`
Console output format.
- **Values**: `txt`, `json`
- **Example**: `logwisp --logging.console.format json`

## Pipeline Options

Configure pipelines via CLI (N = array index, 0-based):

### `--pipelines.N.name <name>`
Pipeline name.
- **Example**: `logwisp --pipelines.0.name myapp`

### `--pipelines.N.sources.N.type <type>`
Source type.
- **Example**: `logwisp --pipelines.0.sources.0.type directory`

### `--pipelines.N.sources.N.options.<key> <value>`
Source options.
- **Example**: `logwisp --pipelines.0.sources.0.options.path /var/log`

### `--pipelines.N.filters.N.type <type>`
Filter type.
- **Example**: `logwisp --pipelines.0.filters.0.type include`

### `--pipelines.N.filters.N.patterns <json>`
Filter patterns (JSON array).
- **Example**: `logwisp --pipelines.0.filters.0.patterns '["ERROR","WARN"]'`

### `--pipelines.N.sinks.N.type <type>`
Sink type.
- **Example**: `logwisp --pipelines.0.sinks.0.type http`

### `--pipelines.N.sinks.N.options.<key> <value>`
Sink options.
- **Example**: `logwisp --pipelines.0.sinks.0.options.port 8080`

## Examples

### Basic Usage
```bash
# Default configuration
logwisp

# Specific configuration
logwisp --config /etc/logwisp/production.toml
```

### Development
```bash
# Debug mode
logwisp --logging.output stderr --logging.level debug

# With file output
logwisp --logging.output both --logging.level debug --logging.file.directory ./debug-logs
```

### Production
```bash
# File logging
logwisp --logging.output file --logging.file.directory /var/log/logwisp

# Background with router
logwisp --background --router --config /etc/logwisp/prod.toml

# Quiet mode for cron
logwisp --quiet --config /etc/logwisp/batch.toml
```

### Pipeline Configuration via CLI
```bash
# Simple pipeline
logwisp --pipelines.0.name app \
        --pipelines.0.sources.0.type directory \
        --pipelines.0.sources.0.options.path /var/log/app \
        --pipelines.0.sinks.0.type http \
        --pipelines.0.sinks.0.options.port 8080

# With filters
logwisp --pipelines.0.name filtered \
        --pipelines.0.sources.0.type stdin \
        --pipelines.0.filters.0.type include \
        --pipelines.0.filters.0.patterns '["ERROR","CRITICAL"]' \
        --pipelines.0.sinks.0.type stdout
```

## Priority Order

1. **Command-line flags** (highest)
2. **Environment variables**
3. **Configuration file**
4. **Built-in defaults** (lowest)

## Exit Codes

- `0`: Success
- `1`: General error
- `2`: Configuration file not found
- `137`: SIGKILL received

## Signals

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown
- `SIGHUP`: Reload configuration (when auto-reload enabled)
- `SIGUSR1`: Reload configuration (when auto-reload enabled)
- `SIGKILL`: Immediate shutdown (exit code 137)