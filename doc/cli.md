# Command Line Interface

LogWisp CLI options for controlling behavior without modifying configuration files.

## Synopsis

```bash
logwisp [options]
```

## General Options

### `--config <path>`
Configuration file location.
- **Default**: `~/.config/logwisp.toml`
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

## Logging Options

Override configuration file settings:

### `--log-output <mode>`
LogWisp's operational log output.
- **Values**: `file`, `stdout`, `stderr`, `both`, `none`
- **Example**: `logwisp --log-output both`

### `--log-level <level>`
Minimum log level.
- **Values**: `debug`, `info`, `warn`, `error`
- **Example**: `logwisp --log-level debug`

### `--log-file <path>`
Log file path (with file output).
- **Example**: `logwisp --log-file /var/log/logwisp/app.log`

### `--log-dir <directory>`
Log directory (with file output).
- **Example**: `logwisp --log-dir /var/log/logwisp`

### `--log-console <target>`
Console output destination.
- **Values**: `stdout`, `stderr`, `split`
- **Example**: `logwisp --log-console split`

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
logwisp --log-output stderr --log-level debug

# With file output
logwisp --log-output both --log-level debug --log-dir ./debug-logs
```

### Production
```bash
# File logging
logwisp --log-output file --log-dir /var/log/logwisp

# Background with router
logwisp --background --router --config /etc/logwisp/prod.toml
```

## Priority Order

1. **Command-line flags** (highest)
2. **Environment variables**
3. **Configuration file**
4. **Built-in defaults** (lowest)

## Exit Codes

- `0`: Success
- `1`: General error
- `2`: Invalid arguments

## Signals

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown