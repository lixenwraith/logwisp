# LogWisp

A high-performance, pipeline-based log transport and processing system built in Go. LogWisp provides flexible log collection, filtering, formatting, and distribution with security and reliability features.

## Features

### Core Capabilities
- **Pipeline Architecture**: Independent processing pipelines with source(s) → filter → format → sink(s) flow
- **Multiple Input Sources**: Directory monitoring, stdin, HTTP, TCP
- **Flexible Output Sinks**: Console, file, HTTP SSE, TCP streaming, HTTP/TCP forwarding
- **Real-time Processing**: Sub-millisecond latency with configurable buffering
- **Hot Configuration Reload**: Update pipelines without service restart

### Data Processing
- **Pattern-based Filtering**: Chainable include/exclude filters with regex support
- **Multiple Formatters**: Raw, JSON, and template-based text formatting
- **Rate Limiting**: Pipeline rate controls

### Security & Reliability  
- **Authentication**: mTLS support
- **Access Control**: IP whitelisting/blacklisting, connection limits
- **TLS Encryption**: Full TLS 1.2/1.3 support for HTTP connections
- **Automatic Reconnection**: Resilient client connections with exponential backoff
- **File Rotation**: Size-based rotation with retention policies

### Operational Features
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
- [Security](security.md) - IP-based access control configuration and mTLS
- [Networking](networking.md) - TLS, rate limiting, and network features
- [Command Line Interface](cli.md) - CLI flags and subcommands
- [Operations Guide](operations.md) - Running and maintaining LogWisp

## Quick Start

Install LogWisp and create a basic configuration:

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

Run with: `logwisp -c config.toml`

## System Requirements

- **Operating Systems**: Linux (kernel 6.10+), FreeBSD (14.0+)
- **Architecture**: amd64
- **Go Version**: 1.25+ (for building from source)

## License

BSD 3-Clause License