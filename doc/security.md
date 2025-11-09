# Security

## mTLS (Mutual TLS)

Certificate-based authentication for HTTPS.

### Server Configuration

```toml
[pipelines.sources.http.tls]
enabled = true
cert_file = "/path/to/server.pem"
key_file = "/path/to/server.key"
client_auth = true
client_ca_file = "/path/to/ca.pem"
verify_client_cert = true
```

### Client Configuration

```toml
[pipelines.sinks.http_client.tls]
enabled = true
cert_file = "/path/to/client.pem"
key_file = "/path/to/client.key"
```

### Certificate Generation

Use the `tls` command:
```bash
# Generate CA
logwisp tls -ca -o ca

# Generate server certificate
logwisp tls -server -ca-cert ca.pem -ca-key ca.key -host localhost -o server

# Generate client certificate
logwisp tls -client -ca-cert ca.pem -ca-key ca.key -o client
```

## Access Control

ogWisp provides IP-based access control for network connections.

+## IP-Based Access Control

Configure IP-based access control for sources:
```toml
 [pipelines.sources.http.net_limit]
 enabled = true
 ip_whitelist = ["192.168.1.0/24", "10.0.0.0/8"]
 ip_blacklist = ["192.168.1.100"]
```

Priority order:
1. Blacklist (checked first, immediate deny)
2. Whitelist (if configured, must match)