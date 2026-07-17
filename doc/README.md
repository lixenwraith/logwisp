# LogWisp

A pipeline-based log transport and processing system built in Go. LogWisp provides flexible log collection, filtering, formatting, and distribution with security and reliability features.

## Features

### Core Capabilities
- **Pipeline Architecture**: Independent processing pipelines with source(s) → filter → format → sink(s) flow
- **Multiple Input Sources**: File monitoring, console (stdin), random log generation, null
- **Flexible Output Sinks**: Console, file, HTTP SSE, TCP streaming, null
- **Real-time Processing**: Sub-millisecond latency with configurable buffering
- **Hot Configuration Reload**: Update pipelines without service restart
- **Session Management**: Built-in session tracking for multiple client connections

### Data Processing
- **Pattern-based Filtering**: Chainable include/exclude filters with regex support
- **Multiple Formatters**: Raw, JSON, and text formatting with integrated sanitizer policies
- **Rate Limiting**: Pipeline rate controls
- **Heartbeat Generation**: Flow-level heartbeat events for keep-alives

### Security & Reliability  
- **File Rotation**: Size-based rotation with retention policies
- **Status Monitoring**: Real-time statistics and health endpoints
- **Signal Handling**: Graceful shutdown and configuration reload via signals
- **Background Mode**: Daemon operation with proper signal handling
- **Quiet Mode**: Silent operation for automated deployments

## Documentation

- [Installation Guide](installation.md) - Platform setup and service configuration
- [Architecture Overview](architecture.md) - System design and component interaction  
- [Configuration Reference](configuration.md) - TOML structure and configuration methods
- [Input Sources](sources.md) - Available source types and configurations
- [Output Sinks](sinks.md) - Sink types and output options
- [Filters](filters.md) - Pattern-based log filtering
- [Formatters](formatters.md) - Log formatting and transformation
- [Networking & Security](networking.md) - Network features (Note: TLS and Auth are currently placeholders in the new architecture)
- [Command Line Interface](cli.md) - CLI flags and subcommands
- [Operations Guide](operations.md) - Running and maintaining LogWisp

## Quick Start

Install LogWisp and create a basic configuration:

```toml
[[pipelines]]
name = "default"

[[pipelines.plugin_sources]]
id = "default_source"
type = "file"
[pipelines.plugin_sources.config]
directory = "./"
pattern = "*.log"

[[pipelines.plugin_sinks]]
id = "default_sink"
type = "console"
[pipelines.plugin_sinks.config]
target = "stdout"
```

Run with: `logwisp -c config.toml`

## System Requirements

- **Operating Systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go Version**: 1.25+ (for building from source)

## License

BSD 3-Clause License
