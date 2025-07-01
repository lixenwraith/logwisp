# Directory structure:

```
logwisp/
├── build.sh
├── go.mod
├── go.sum
├── README.md
├── test_logwisp.sh
├── examples/
│   └── env_usage.sh
└── src/
├── cmd/
│   └── logwisp/
│       └── main.go
└── internal/
├── config/
│   └── config.go         # Uses LixenWraith/config
├── middleware/
│   └── ratelimit.go      # Rate limiting middleware
├── monitor/
│   └── monitor.go        # Enhanced file/directory monitoring
└── stream/
└── stream.go         # SSE streaming handler
```

# Configuration locations:
~/.config/logwisp.toml           # Default config location
$LOGWISP_CONFIG_DIR/             # Override via environment
$LOGWISP_CONFIG_FILE             # Override via environment

# Environment variables:
LOGWISP_CONFIG_DIR               # Config directory override
LOGWISP_CONFIG_FILE              # Config filename override
LOGWISP_PORT                     # Port override
LOGWISP_MONITOR_CHECK_INTERVAL_MS # Check interval override
LOGWISP_MONITOR_TARGETS          # Targets override (special format)
LOGWISP_STREAM_BUFFER_SIZE       # Buffer size override
LOGWISP_STREAM_RATE_LIMIT_*      # Rate limit overrides