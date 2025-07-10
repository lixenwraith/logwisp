<table>
  <tr>
    <td width="200" valign="middle">
      <img src="asset/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
    </td>
    <td valign="middle">
      <h1>LogWisp</h1>
      <p>
        <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat&logo=go" alt="Go"></a>
        <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
        <a href="doc/"><img src="https://img.shields.io/badge/Docs-Available-green.svg" alt="Documentation"></a>
      </p>
    </td>
  </tr>
</table>


**Multi-stream log monitoring with real-time streaming over HTTP/SSE and TCP**

LogWisp watches log files and streams updates to connected clients in real-time. Perfect for monitoring multiple applications, filtering noise, and centralizing log access.

## 🚀 Quick Start

```bash
# Install
go install github.com/yourusername/logwisp/src/cmd/logwisp@latest

# Run with defaults (monitors *.log in current directory)
logwisp

# Stream logs (from another terminal)
curl -N http://localhost:8080/stream
```

## ✨ Key Features

- **📡 Real-time Streaming** - SSE (HTTP) and TCP protocols
- **🔍 Pattern Filtering** - Include/exclude logs with regex patterns
- **🛡️ Rate Limiting** - Protect against abuse with configurable limits
- **📊 Multi-stream** - Monitor different log sources simultaneously
- **🔄 Rotation Aware** - Handles log rotation seamlessly
- **⚡ High Performance** - Minimal CPU/memory footprint

## 📖 Documentation

Complete documentation is available in the [`doc/`](doc/) directory:

- [**Quick Start Guide**](doc/quickstart.md) - Get running in 5 minutes
- [**Configuration**](doc/configuration.md) - All configuration options
- [**CLI Reference**](doc/cli.md) - Command-line interface
- [**Examples**](doc/examples/) - Ready-to-use configurations

## 💻 Basic Usage

### Monitor application logs with filtering:

```toml
# ~/.config/logwisp.toml
[[streams]]
name = "myapp"

[streams.monitor]
targets = [{ path = "/var/log/myapp", pattern = "*.log" }]

[[streams.filters]]
type = "include"
patterns = ["ERROR", "WARN", "CRITICAL"]

[streams.httpserver]
enabled = true
port = 8080
```

### Run multiple streams:

```bash
logwisp --router --config /etc/logwisp/multi-stream.toml
```

## 📄 License

BSD-3-Clause