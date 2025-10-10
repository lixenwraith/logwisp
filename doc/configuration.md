# Configuration Reference

LogWisp configuration uses TOML format with flexible override mechanisms.

## Configuration Precedence

Configuration sources are evaluated in order:
1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Built-in defaults** (lowest priority)

## File Location

LogWisp searches for configuration in order:
1. Path specified via `--config` flag
2. Path from `LOGWISP_CONFIG_FILE` environment variable
3. `~/.config/logwisp/logwisp.toml`
4. `./logwisp.toml` in current directory

## Global Settings

Top-level configuration options:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `background` | bool | false | Run as daemon process |
| `quiet` | bool | false | Suppress console output |
| `disable_status_reporter` | bool | false | Disable periodic status logging |
| `config_auto_reload` | bool | false | Enable file watch for auto-reload |

## Logging Configuration

LogWisp's internal operational logging:

```toml
[logging]
output = "stdout"  # file|stdout|stderr|split|all|none
level = "info"     # debug|info|warn|error

[logging.file]
directory = "./log"
name = "logwisp"
max_size_mb = 100
max_total_size_mb = 1000
retention_hours = 168.0

[logging.console]
target = "stdout"  # stdout|stderr|split
format = "txt"     # txt|json
```

### Output Modes

- **file**: Write to log files only
- **stdout**: Write to standard output
- **stderr**: Write to standard error
- **split**: INFO/DEBUG to stdout, WARN/ERROR to stderr
- **all**: Write to both file and console
- **none**: Disable all logging

## Pipeline Configuration

Each `[[pipelines]]` section defines an independent processing pipeline:

```toml
[[pipelines]]
name = "pipeline-name"

# Rate limiting (optional)
[pipelines.rate_limit]
rate = 1000.0
burst = 2000.0
policy = "drop"  # pass|drop
max_entry_size_bytes = 0  # 0=unlimited

# Format configuration (optional)
[pipelines.format]
type = "json"  # raw|json|txt

# Sources (required, 1+)
[[pipelines.sources]]
type = "directory"
# ... source-specific config

# Filters (optional)
[[pipelines.filters]]
type = "include"
logic = "or"
patterns = ["ERROR", "WARN"]

# Sinks (required, 1+)
[[pipelines.sinks]]
type = "http"
# ... sink-specific config
```

## Environment Variables

All configuration options support environment variable overrides:

### Naming Convention

- Prefix: `LOGWISP_`
- Path separator: `_` (underscore)
- Array indices: Numeric suffix (0-based)
- Case: UPPERCASE

### Mapping Examples

| TOML Path | Environment Variable |
|-----------|---------------------|
| `quiet` | `LOGWISP_QUIET` |
| `logging.level` | `LOGWISP_LOGGING_LEVEL` |
| `pipelines[0].name` | `LOGWISP_PIPELINES_0_NAME` |
| `pipelines[0].sources[0].type` | `LOGWISP_PIPELINES_0_SOURCES_0_TYPE` |

## Command-Line Overrides

All configuration options can be overridden via CLI flags:

```bash
logwisp --quiet \
  --logging.level=debug \
  --pipelines.0.name=myapp \
  --pipelines.0.sources.0.type=stdin
```

## Configuration Validation

LogWisp validates configuration at startup:
- Required fields presence
- Type correctness
- Port conflicts
- Path accessibility
- Pattern compilation
- Network address formats

## Hot Reload

Enable configuration hot reload:

```toml
config_auto_reload = true
```

Or via command line:
```bash
logwisp --config-auto-reload
```

Reload triggers:
- File modification detection
- SIGHUP or SIGUSR1 signals

Reloadable items:
- Pipeline configurations
- Sources and sinks
- Filters and formatters
- Rate limits

Non-reloadable (requires restart):
- Logging configuration
- Background mode
- Global settings

## Default Configuration

Minimal working configuration:

```toml
[[pipelines]]
name = "default"

[[pipelines.sources]]
type = "directory"
[pipelines.sources.directory]
path = "./"
pattern = "*.log"

[[pipelines.sinks]]
type = "console"
[pipelines.sinks.console]
target = "stdout"
```

## Configuration Schema

### Type Reference

| TOML Type | Go Type | Environment Format |
|-----------|---------|-------------------|
| String | string | Plain text |
| Integer | int64 | Numeric string |
| Float | float64 | Decimal string |
| Boolean | bool | true/false |
| Array | []T | JSON array string |
| Table | struct | Nested with `_` |