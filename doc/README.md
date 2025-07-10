# LogWisp Documentation

Welcome to the LogWisp documentation. This guide covers all aspects of installing, configuring, and using LogWisp for multi-stream log monitoring.

## 📚 Documentation Index

### Getting Started
- **[Installation Guide](installation.md)** - How to install LogWisp on various platforms
- **[Quick Start](quickstart.md)** - Get up and running in 5 minutes
- **[Architecture Overview](architecture.md)** - System design and components

### Configuration
- **[Configuration Guide](configuration.md)** - Complete configuration reference
- **[Environment Variables](environment.md)** - Environment variable reference
- **[Command Line Options](cli.md)** - CLI flags and parameters

### Features
- **[Filters Guide](filters.md)** - Pattern-based log filtering
- **[Rate Limiting](ratelimiting.md)** - Request and connection limiting
- **[Router Mode](router.md)** - Path-based multi-stream routing
- **[Authentication](authentication.md)** - Securing your log streams *(planned)*

### Operations
- **[Monitoring & Status](monitoring.md)** - Health checks and statistics
- **[Performance Tuning](performance.md)** - Optimization guidelines
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

### Advanced Topics
- **[Security Best Practices](security.md)** - Hardening your deployment
- **[Integration Examples](integrations.md)** - Working with other tools
- **[Development Guide](development.md)** - Contributing to LogWisp

## 🚀 Quick Links

- **[Example Configurations](examples/)** - Ready-to-use config templates
- **[API Reference](api.md)** - SSE/TCP protocol documentation
- **[Changelog](../CHANGELOG.md)** - Version history and updates

## 💡 Common Use Cases

### Single Application Monitoring
Monitor logs from one application with basic filtering:
```toml
[[streams]]
name = "myapp"
[streams.monitor]
targets = [{ path = "/var/log/myapp", pattern = "*.log" }]
[[streams.filters]]
type = "include"
patterns = ["ERROR", "WARN"]
```

### Multi-Service Architecture
Monitor multiple services with different configurations:
```bash
logwisp --router --config /etc/logwisp/services.toml
```

### High-Security Environments
Enable authentication and rate limiting:
```toml
[streams.httpserver.rate_limit]
enabled = true
requests_per_second = 10.0
max_connections_per_ip = 3
```

## 🔍 Finding Help

- **GitHub Issues**: [Report bugs or request features](https://github.com/logwisp/logwisp/issues)
- **Discussions**: [Ask questions and share ideas](https://github.com/logwisp/logwisp/discussions)
- **Examples**: Check the [examples directory](examples/) for common scenarios

## 📝 License

BSD-3-Clause