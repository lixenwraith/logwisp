# Architecture Overview

LogWisp implements a pipeline-based architecture for flexible log processing and distribution.

## Core Concepts

### Pipeline Model

Each pipeline operates independently with a source → filter → format → sink flow. Multiple pipelines can run concurrently within a single LogWisp instance, each processing different log streams with unique configurations.

### Component Hierarchy

```
Service (Main Process)
├── Pipeline 1
│   ├── Sources (1 or more)
│   ├── Rate Limiter (optional)
│   ├── Filter Chain (optional)
│   ├── Formatter (optional)
│   └── Sinks (1 or more)
├── Pipeline 2
│   └── [Same structure]
└── Status Reporter (optional)
```

## Data Flow

### Processing Stages

1. **Source Stage**: Sources monitor inputs and generate log entries
2. **Rate Limiting**: Optional pipeline-level rate control
3. **Filtering**: Pattern-based inclusion/exclusion
4. **Formatting**: Transform entries to desired output format
5. **Distribution**: Fan-out to multiple sinks

### Entry Lifecycle

Log entries flow through the pipeline as `core.LogEntry` structures containing:
- **Time**: Entry timestamp
- **Level**: Log level (DEBUG, INFO, WARN, ERROR)
- **Source**: Origin identifier
- **Message**: Log content
- **Fields**: Additional metadata (JSON)
- **RawSize**: Original entry size

### Buffering Strategy

Each component maintains internal buffers to handle burst traffic:
- Sources: Configurable buffer size (default 1000 entries)
- Sinks: Independent buffers per sink
- Network components: Additional TCP/HTTP buffers

## Component Types

### Sources (Input)

- **Directory Source**: File system monitoring with rotation detection
- **Stdin Source**: Standard input processing
- **HTTP Source**: REST endpoint for log ingestion
- **TCP Source**: Raw TCP socket listener

### Sinks (Output)

- **Console Sink**: stdout/stderr output
- **File Sink**: Rotating file writer
- **HTTP Sink**: Server-Sent Events (SSE) streaming
- **TCP Sink**: TCP server for client connections
- **HTTP Client Sink**: Forward to remote HTTP endpoints
- **TCP Client Sink**: Forward to remote TCP servers

### Processing Components

- **Rate Limiter**: Token bucket algorithm for flow control
- **Filter Chain**: Sequential pattern matching
- **Formatters**: Raw, JSON, or template-based text transformation

## Concurrency Model

### Goroutine Architecture

- Each source runs in dedicated goroutines for monitoring
- Sinks operate independently with their own processing loops
- Network listeners use optimized event loops (gnet for TCP)
- Pipeline processing uses channel-based communication

### Synchronization

- Atomic counters for statistics
- Read-write mutexes for configuration access
- Context-based cancellation for graceful shutdown
- Wait groups for coordinated startup/shutdown

## Network Architecture

### Connection Patterns

**Chaining Design**:
- TCP Client Sink → TCP Source: Direct TCP forwarding
- HTTP Client Sink → HTTP Source: HTTP-based forwarding

**Monitoring Design**:
- TCP Sink: Debugging interface
- HTTP Sink: Browser-based live monitoring

### Protocol Support

- HTTP/1.1 and HTTP/2 for HTTP connections
- Raw TCP connections
- TLS 1.2/1.3 for HTTPS connections (HTTP only)
- Server-Sent Events for real-time streaming

## Resource Management

### Memory Management

- Bounded buffers prevent unbounded growth
- Automatic garbage collection via Go runtime
- Connection limits prevent resource exhaustion

### File Management

- Automatic rotation based on size thresholds
- Retention policies for old log files
- Minimum disk space checks before writing

### Connection Management

- Per-IP connection limits
- Global connection caps
- Automatic reconnection with exponential backoff
- Keep-alive for persistent connections

## Reliability Features

### Fault Tolerance

- Panic recovery in pipeline processing
- Independent pipeline operation
- Automatic source restart on failure
- Sink failure isolation

### Data Integrity

- Entry validation at ingestion
- Size limits for entries and batches
- Duplicate detection in file monitoring
- Position tracking for file reads

## Performance Characteristics

### Throughput

- Pipeline rate limiting: Configurable (default 1000 entries/second)
- Network throughput: Limited by network and sink capacity
- File monitoring: Sub-second detection (default 100ms interval)

### Latency

- Entry processing: Sub-millisecond in-memory
- Network forwarding: Depends on batch configuration
- File detection: Configurable check interval

### Scalability

- Horizontal: Multiple LogWisp instances with different configurations
- Vertical: Multiple pipelines per instance
- Fan-out: Multiple sinks per pipeline
- Fan-in: Multiple sources per pipeline