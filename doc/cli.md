# Command Line Interface

LogWisp provides a comprehensive set of command-line options for controlling its behavior without modifying configuration files.

## Synopsis

```bash
logwisp [options]
```

## General Options

### `--config <path>`
Specify the configuration file location.
- **Default**: `~/.config/logwisp.toml`
- **Example**: `logwisp --config /etc/logwisp/production.toml`

### `--router`
Enable HTTP router mode for path-based routing of multiple streams.
- **Default**: `false` (standalone mode)
- **Use case**: Consolidate multiple HTTP streams on shared ports
- **Example**: `logwisp --router`

### `--version`
Display version information and exit.
- **Example**: `logwisp --version`

### `--background`
Run LogWisp as a background process.
- **Default**: `false` (foreground mode)
- **Example**: `logwisp --background`

## Logging Options

These options override the corresponding configuration file settings.

### `--log-output <mode>`
Control where LogWisp writes its own operational logs.
- **Values**: `file`, `stdout`, `stderr`, `both`, `none`
- **Default**: Configured value or `stderr`
- **Example**: `logwisp --log-output both`

#### Output Modes:
- `file`: Write logs only to files
- `stdout`: Write logs only to standard output
- `stderr`: Write logs only to standard error
- `both`: Write logs to both files and console
- `none`: Disable logging (⚠️ SECURITY: Not recommended)

### `--log-level <level>`
Set the minimum log level for LogWisp's operational logs.
- **Values**: `debug`, `info`, `warn`, `error`
- **Default**: Configured value or `info`
- **Example**: `logwisp --log-level debug`

### `--log-file <path>`
Specify the log file path when using file output.
- **Default**: Configured value or `./logs/logwisp.log`
- **Example**: `logwisp --log-output file --log-file /var/log/logwisp/app.log`

### `--log-dir <directory>`
Specify the log directory when using file output.
- **Default**: Configured value or `./logs`
- **Example**: `logwisp --log-output file --log-dir /var/log/logwisp`

### `--log-console <target>`
Control console output destination when using `stdout`, `stderr`, or `both` modes.
- **Values**: `stdout`, `stderr`, `split`
- **Default**: `stderr`
- **Example**: `logwisp --log-output both --log-console split`

#### Console Targets:
- `stdout`: All logs to standard output
- `stderr`: All logs to standard error
- `split`: INFO/DEBUG to stdout, WARN/ERROR to stderr (planned)

## Examples

### Basic Usage
```bash
# Start with default configuration
logwisp

# Use a specific configuration file
logwisp --config /etc/logwisp/production.toml
```

### Development Mode
```bash
# Enable debug logging to console
logwisp --log-output stderr --log-level debug

# Debug with file output
logwisp --log-output both --log-level debug --log-dir ./debug-logs
```

### Production Deployment
```bash
# File logging with info level
logwisp --log-output file --log-dir /var/log/logwisp --log-level info

# Background mode with custom config
logwisp --background --config /etc/logwisp/prod.toml

# Router mode for multiple services
logwisp --router --config /etc/logwisp/services.toml
```

### Troubleshooting
```bash
# Maximum verbosity to stderr
logwisp --log-output stderr --log-level debug

# Check version
logwisp --version

# Test configuration without backgrounding
logwisp --config test.toml --log-level debug
```

## Priority Order

Configuration values are applied in the following priority order (highest to lowest):

1. **Command-line flags** - Explicitly specified options
2. **Environment variables** - `LOGWISP_*` prefixed variables
3. **Configuration file** - TOML configuration
4. **Built-in defaults** - Hardcoded fallback values

## Exit Codes

- `0`: Successful execution
- `1`: General error (configuration, startup failure)
- `2`: Invalid command-line arguments

## Signals

LogWisp responds to the following signals:

- `SIGINT` (Ctrl+C): Graceful shutdown
- `SIGTERM`: Graceful shutdown
- `SIGKILL`: Immediate termination (not recommended)

During graceful shutdown, LogWisp will:
1. Stop accepting new connections
2. Finish streaming to existing clients
3. Flush all buffers
4. Close all file handles
5. Exit cleanly

## See Also

- [Configuration Guide](configuration.md) - Complete configuration reference
- [Environment Variables](environment.md) - Environment variable options
- [Router Mode](router.md) - Path-based routing details