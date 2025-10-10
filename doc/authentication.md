# Authentication

LogWisp supports multiple authentication methods for securing network connections.

## Authentication Methods

### Overview

| Method | HTTP Source | HTTP Sink | HTTP Client | TCP Source | TCP Client | TCP Sink |
|--------|------------|-----------|-------------|------------|------------|----------|
| None | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Basic | ✓ (TLS req) | ✓ (TLS req) | ✓ (TLS req) | ✗ | ✗ | ✗ |
| Token | ✓ (TLS req) | ✓ (TLS req) | ✓ (TLS req) | ✗ | ✗ | ✗ |
| SCRAM | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ |
| mTLS | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |

**Important Notes:**
- HTTP authentication **requires** TLS to be enabled
- TCP connections are **always** unencrypted
- TCP Sink has **no** authentication (debugging only)

## Basic Authentication

HTTP/HTTPS connections with username/password.

### Configuration

```toml
[pipelines.sources.http.auth]
type = "basic"
realm = "LogWisp"

[[pipelines.sources.http.auth.basic.users]]
username = "admin"
password_hash = "$argon2id$v=19$m=65536,t=3,p=2$..."
```

### Generating Credentials

Use the `auth` command:
```bash
logwisp auth -u admin -b
```

Output includes:
- Argon2id password hash for configuration
- TOML configuration snippet

### Password Hash Format

LogWisp uses Argon2id with parameters:
- Memory: 65536 KB
- Iterations: 3
- Parallelism: 2
- Salt: Random 16 bytes

## Token Authentication

Bearer token authentication for HTTP/HTTPS.

### Configuration

```toml
[pipelines.sources.http.auth]
type = "token"

[pipelines.sources.http.auth.token]
tokens = ["token1", "token2", "token3"]
```

### Generating Tokens

```bash
logwisp auth -k -l 32
```

Generates:
- Base64-encoded token
- Hex-encoded token
- Configuration snippet

### Token Usage

Include in requests:
```
Authorization: Bearer <token>
```

## SCRAM Authentication

Secure Challenge-Response for TCP connections.

### Configuration

```toml
[pipelines.sources.tcp.auth]
type = "scram"

[[pipelines.sources.tcp.auth.scram.users]]
username = "tcpuser"
stored_key = "base64..."
server_key = "base64..."
salt = "base64..."
argon_time = 3
argon_memory = 65536
argon_threads = 4
```

### Generating SCRAM Credentials

```bash
logwisp auth -u tcpuser -s
```

### SCRAM Features

- Argon2-SCRAM-SHA256 algorithm
- Challenge-response mechanism
- No password transmission
- Replay attack protection
- Works over unencrypted connections

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

[pipelines.sources.http.auth]
type = "mtls"
```

### Client Configuration

```toml
[pipelines.sinks.http_client.tls]
enabled = true
cert_file = "/path/to/client.pem"
key_file = "/path/to/client.key"

[pipelines.sinks.http_client.auth]
type = "mtls"
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

## Authentication Command

### Usage

```bash
logwisp auth [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-u, --user` | Username for credential generation |
| `-p, --password` | Password (prompts if not provided) |
| `-b, --basic` | Generate basic auth (HTTP/HTTPS) |
| `-s, --scram` | Generate SCRAM auth (TCP) |
| `-k, --token` | Generate bearer token |
| `-l, --length` | Token length in bytes (default: 32) |

### Security Best Practices

1. **Always use TLS** for HTTP authentication
2. **Never hardcode passwords** in configuration
3. **Use strong passwords** (minimum 12 characters)
4. **Rotate tokens regularly**
5. **Limit user permissions** to minimum required
6. **Store password hashes only**, never plaintext
7. **Use unique credentials** per service/user

## Access Control Lists

Combine authentication with IP-based access control:

```toml
[pipelines.sources.http.net_limit]
enabled = true
ip_whitelist = ["192.168.1.0/24", "10.0.0.0/8"]
ip_blacklist = ["192.168.1.100"]
```

Priority order:
1. Blacklist (checked first, immediate deny)
2. Whitelist (if configured, must match)
3. Authentication (if configured)

## Credential Storage

### Configuration File

Store hashes in TOML:
```toml
[[pipelines.sources.http.auth.basic.users]]
username = "admin"
password_hash = "$argon2id$..."
```

### Environment Variables

Override via environment:
```bash
export LOGWISP_PIPELINES_0_SOURCES_0_HTTP_AUTH_BASIC_USERS_0_USERNAME=admin
export LOGWISP_PIPELINES_0_SOURCES_0_HTTP_AUTH_BASIC_USERS_0_PASSWORD_HASH='$argon2id$...'
```

### External Files

Future support planned for:
- External user databases
- LDAP/AD integration
- OAuth2/OIDC providers