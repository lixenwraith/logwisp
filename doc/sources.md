# Input Sources

LogWisp sources monitor various inputs and generate log entries for pipeline processing.

## Source Types

### Directory Source

Monitors a directory for log files matching a pattern. (type: `file`)

```toml
[[pipelines.plugin_sources]]
id = "file_in"
type = "file"
[pipelines.plugin_sources.config]
directory = "/var/log/myapp"
pattern = "*.log"          # Glob pattern
check_interval_ms = 100    # Poll interval
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `directory` | string | Required | Directory to monitor |
| `pattern` | string | "*" | File pattern (glob) |
| `check_interval_ms` | int | 100 | File check interval in milliseconds |

**Features:**
- Automatic rotation detection (inode + size tracking)
- In-memory position tracking; on restart, monitoring resumes from the current end of each file (offsets are not persisted)
- Concurrent file monitoring
- Pattern-based file selection

### Stdin Source

Reads log entries from standard input.

```toml
[[pipelines.plugin_sources]]
id = "console_in"
type = "console"
[pipelines.plugin_sources.config]
buffer_size = 1000
```

**Configuration Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `buffer_size` | int | 1000 | Internal buffer size |

**Features:**
- Line-based processing
- Automatic level detection
- Non-blocking reads

### Random Source

```toml
[[pipelines.plugin_sources]]
id = "random_in"
type = "random"
[pipelines.plugin_sources.config]
interval_ms = 500
jitter_ms = 0
format = "txt"
length = 20
special = false
```

 **Configuration Options:**
 
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `interval_ms` | int | 500 | Generation interval |
| `jitter_ms` | int | 0 | Random jitter interval |
| `format` | string | "txt" | "txt", "json", "raw" |
| `length` | int | 20 | Log length |
| `special` | bool | false | Include special characters |
 
## Source Statistics

All sources track:
- Total entries received
- Dropped entries (buffer full)
- Invalid entries
- Last entry timestamp
- Active connections (network sources)
- Source-specific metrics

### Null Source

```toml
[[pipelines.plugin_sources]]
id = "null_in"
type = "null"
[pipelines.plugin_sources.config]
```

## Buffer Management

Each source maintains internal buffers:
- Default size: 1000 entries
- Drop policy when full
- Configurable per source
- Non-blocking writes
