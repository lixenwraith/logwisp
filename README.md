<table>
  <tr>
    <td width="200" valign="middle">
      <img src="asset/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
    </td>
    <td>
      <h1>LogWisp</h1>
      <p>
        <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.25-00ADD8?style=flat&logo=go" alt="Go"></a>
        <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
        <a href="doc/"><img src="https://img.shields.io/badge/Docs-Available-green.svg" alt="Documentation"></a>
      </p>
    </td>
  </tr>
</table>

# LogWisp

A high-performance, pipeline-based log transport and processing system built in Go. LogWisp provides flexible log collection, filtering, formatting, and distribution with enterprise-grade security and reliability features.

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
- **Rate Limiting**: Pipeline rate control

### Security & Reliability
- **Authentication**: mTLS support for HTTPS
- **TLS Encryption**: TLS 1.2/1.3 support for HTTP connections
- **Access Control**: IP whitelisting/blacklisting, connection limits
- **Automatic Reconnection**: Resilient client connections with exponential backoff
- **File Rotation**: Size-based rotation with retention policies

### Operational Features
- **Status Monitoring**: Real-time statistics and health endpoints
- **Signal Handling**: Graceful shutdown and configuration reload via signals
- **Background Mode**: Daemon operation with proper signal handling
- **Quiet Mode**: Silent operation for automated deployments

## Documentation

Available in `doc/` directory.

- [Installation Guide](doc/installation.md) - Platform setup and service configuration
- [Architecture Overview](doc/architecture.md) - System design and component interaction
- [Configuration Reference](doc/configuration.md) - TOML structure and configuration methods
- [Input Sources](doc/sources.md) - Available source types and configurations
- [Output Sinks](doc/sinks.md) - Sink types and output options
- [Filters](doc/filters.md) - Pattern-based log filtering
- [Formatters](doc/formatters.md) - Log formatting and transformation
- [Security](doc/security.md) - mTLS configurations and access control
- [Networking](doc/networking.md) - TLS, rate limiting, and network features
- [Command Line Interface](doc/cli.md) - CLI flags and subcommands
- [Operations Guide](doc/operations.md) - Running and maintaining LogWisp

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