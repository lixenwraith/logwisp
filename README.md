<table>
  <tr>
    <td width="200" valign="middle">
      <img src="asset/logwisp-logo.svg" alt="LogWisp Logo" width="200"/>
    </td>
    <td>
      <h1>LogWisp</h1>
      <p>
        <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat&logo=go" alt="Go"></a>
        <a href="https://opensource.org/licenses/BSD-3-Clause"><img src="https://img.shields.io/badge/License-BSD_3--Clause-blue.svg" alt="License"></a>
        <a href="doc/"><img src="https://img.shields.io/badge/Docs-Available-green.svg" alt="Documentation"></a>
      </p>
    </td>
  </tr>
</table>

**Flexible log monitoring with real-time streaming over HTTP/SSE and TCP**

LogWisp watches log files and streams updates to connected clients in real-time using a pipeline architecture: **sources → filters → sinks**. Perfect for monitoring multiple applications, filtering noise, and routing logs to multiple destinations.

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/lixenwraith/logwisp.git
cd logwisp
make install

# Run with defaults (monitors *.log in current directory)
logwisp
```

## ✨ Key Features

- **🔧 Pipeline Architecture** - Flexible source → filter → sink processing
- **📡 Real-time Streaming** - SSE (HTTP) and TCP protocols
- **🔍 Pattern Filtering** - Include/exclude logs with regex patterns
- **🛡️ Rate Limiting** - Protect against abuse with configurable limits
- **📊 Multi-pipeline** - Process different log sources simultaneously
- **🔄 Rotation Aware** - Handles log rotation seamlessly
- **⚡ High Performance** - Minimal CPU/memory footprint

## 📖 Documentation

Complete documentation is available in the [`doc/`](doc/) directory:

- [**Quick Start Guide**](doc/quickstart.md) - Get running in 5 minutes
- [**Configuration**](doc/configuration.md) - All configuration options
- [**CLI Reference**](doc/cli.md) - Command-line interface
- [**Examples**](doc/examples/) - Ready-to-use configurations

## 📄 License

BSD-3-Clause