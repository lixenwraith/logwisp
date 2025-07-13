# Architecture Overview

LogWisp implements a flexible pipeline architecture for real-time log processing and streaming.

## Core Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              LogWisp Service                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────── Pipeline 1 ───────────────────────────┐   │
│  │                                                                  │   │
│  │  Sources           Filters              Sinks                    │   │
│  │  ┌──────┐        ┌────────┐          ┌──────┐                    │   │
│  │  │ Dir  │──┐     │Include │     ┌────│ HTTP │←── Client 1        │   │
│  │  └──────┘  ├────▶│ ERROR  │     │    └──────┘                    │   │
│  │            │     │  WARN  │────▶├────┌──────┐                    │   │
│  │  ┌──────┐  │     └────┬───┘     │    │ File │                    │   │
│  │  │ HTTP │──┤          ▼         │    └──────┘                    │   │
│  │  └──────┘  │     ┌────────┐     │    ┌──────┐                    │   │
│  │  ┌──────┐  │     │Exclude │     └────│ TCP  │←── Client 2        │   │
│  │  │ TCP  │──┘     │ DEBUG  │          └──────┘                    │   │
│  │  └──────┘        └────────┘                                      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────── Pipeline 2 ───────────────────────────┐   │
│  │                                                                  │   │
│  │  ┌──────┐                            ┌───────────┐               │   │
│  │  │Stdin │───────────────────────┬───▶│HTTP Client│──► Remote     │   │
│  │  └──────┘         (No Filters)  │    └───────────┘               │   │
│  │                                 │    ┌───────────┐               │   │
│  │                                 └────│TCP Client │──► Remote     │   │
│  │                                      └───────────┘               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────── Pipeline N ───────────────────────────┐   │
│  │  Multiple Sources → Filter Chain → Multiple Sinks                │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Log Entry Flow:

┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  Source │     │  Parse  │     │ Filter  │     │  Sink   │
│ Monitor │────▶│  Entry  │────▶│  Chain  │────▶│ Deliver │
└─────────┘     └─────────┘     └─────────┘     └─────────┘
     │               │               │               │
     ▼               ▼               ▼               ▼
  Detect         Extract         Include/        Send to
  Input          & Format        Exclude         Clients


Entry Processing:

1. Source Detection     2. Entry Creation      3. Filter Application
   ┌──────────┐           ┌────────────┐         ┌─────────────┐
   │New Entry │           │ Timestamp  │         │  Filter 1   │
   │Detected  │──────────▶│   Level    │────────▶│ Include?    │
   └──────────┘           │  Message   │         └──────┬──────┘
                          └────────────┘                │
                                                        ▼
4. Sink Distribution                             ┌─────────────┐
   ┌──────────┐                                  │  Filter 2   │
   │   HTTP   │◀───┐                             │ Exclude?    │
   └──────────┘    │                             └──────┬──────┘
   ┌──────────┐    │                                    │
   │   TCP    │◀───┼────────── Entry ◀──────────────────┘
   └──────────┘    │           (if passed)
   ┌──────────┐    │
   │   File   │◀───┤
   └──────────┘    │
   ┌──────────┐    │
   │ HTTP/TCP │◀───┘
   │  Client  │
   └──────────┘
```

## Component Details

### Sources

Sources monitor inputs and generate log entries:

```
Directory Source:
┌─────────────────────────────────┐
│        Directory Monitor        │
├─────────────────────────────────┤
│ • Pattern Matching (*.log)      │
│ • File Rotation Detection       │
│ • Position Tracking             │
│ • Concurrent File Watching      │
└─────────────────────────────────┘
           │
           ▼
    ┌──────────────┐
    │ File Watcher │ (per file)
    ├──────────────┤
    │ • Read New   │
    │ • Track Pos  │
    │ • Detect Rot │
    └──────────────┘

HTTP/TCP Sources:
┌─────────────────────────────────┐
│      Network Listener           │
├─────────────────────────────────┤
│ • JSON Parsing                  │
│ • Rate Limiting                 │
│ • Connection Management         │
│ • Input Validation              │
└─────────────────────────────────┘
```

### Filters

Filters process entries through pattern matching:

```
Filter Chain:
                 ┌─────────────┐
Entry ──────────▶│  Filter 1   │
                 │  (Include)  │
                 └──────┬──────┘
                        │ Pass?
                        ▼
                 ┌─────────────┐
                 │  Filter 2   │
                 │  (Exclude)  │
                 └──────┬──────┘
                        │ Pass?
                        ▼
                 ┌─────────────┐
                 │  Filter N   │
                 └──────┬──────┘
                        │
                        ▼
                    To Sinks
```

### Sinks

Sinks deliver processed entries to destinations:

```
HTTP Sink (SSE):
┌───────────────────────────────────┐
│            HTTP Server            │
├───────────────────────────────────┤
│    ┌─────────┐    ┌─────────┐     │
│    │ Stream  │    │ Status  │     │
│    │Endpoint │    │Endpoint │     │
│    └────┬────┘    └────┬────┘     │
│         │              │          │
│    ┌────▼──────────────▼────┐     │
│    │   Connection Manager   │     │
│    ├────────────────────────┤     │
│    │ • Rate Limiting        │     │
│    │ • Heartbeat            │     │
│    │ • Buffer Management    │     │
│    └────────────────────────┘     │
└───────────────────────────────────┘

TCP Sink:
┌───────────────────────────────────┐
│            TCP Server             │
├───────────────────────────────────┤
│    ┌────────────────────────┐     │
│    │    gnet Event Loop     │     │
│    ├────────────────────────┤     │
│    │ • Async I/O            │     │
│    │ • Connection Pool      │     │
│    │ • Rate Limiting        │     │
│    └────────────────────────┘     │
└───────────────────────────────────┘

Client Sinks:
┌───────────────────────────────────┐
│       HTTP/TCP Client             │
├───────────────────────────────────┤
│    ┌────────────────────────┐     │
│    │    Output Manager      │     │
│    ├────────────────────────┤     │
│    │ • Batching             │     │
│    │ • Retry Logic          │     │
│    │ • Connection Pooling   │     │
│    │ • Failover             │     │
│    └────────────────────────┘     │
└───────────────────────────────────┘
```

## Router Mode

In router mode, multiple pipelines share HTTP ports:

```
Router Architecture:
                    ┌─────────────────┐
                    │   HTTP Router   │
                    │    Port 8080    │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   /app/stream          /db/stream         /sys/stream
        │                    │                    │
   ┌────▼────┐          ┌────▼────┐          ┌────▼────┐
   │Pipeline │          │Pipeline │          │Pipeline │
   │  "app"  │          │  "db"   │          │  "sys"  │
   └─────────┘          └─────────┘          └─────────┘

Path Routing:
Client Request ──▶ Router ──▶ Parse Path ──▶ Find Pipeline ──▶ Route
                                  │
                                  ▼
                           Extract Pipeline Name
                           from /pipeline/endpoint
```

## Memory Management

```
Buffer Flow:
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Source  │     │ Pipeline │     │   Sink   │
│  Buffer  │────▶│  Buffer  │────▶│  Buffer  │
│ (1000)   │     │  (chan)  │     │ (1000)   │
└──────────┘     └──────────┘     └──────────┘
     │                │                 │
     ▼                ▼                 ▼
 Drop if full    Backpressure      Drop if full
 (counted)        (blocking)        (counted)

Client Sinks:
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Entry   │     │  Batch   │     │  Send    │
│  Buffer  │────▶│  Buffer  │────▶│  Queue   │
│ (1000)   │     │ (100)    │     │  (retry) │
└──────────┘     └──────────┘     └──────────┘
```

## Rate Limiting

```
Token Bucket Algorithm:
┌─────────────────────────────┐
│        Token Bucket         │
├─────────────────────────────┤
│ Capacity: burst_size        │
│ Refill: requests_per_second │
│                             │
│   ┌─────────────────────┐   │
│   │ ● ● ● ● ● ● ○ ○ ○ ○ │   │
│   └─────────────────────┘   │
│    6/10 tokens available    │
└─────────────────────────────┘
         │
         ▼
   Request arrives
         │
         ▼
   Token available? ──No──▶ Reject (429)
         │
        Yes
         ▼
   Consume token ──▶ Allow request
```

## Concurrency Model

```
Goroutine Structure:

Main ────┬──── Pipeline 1 ────┬──── Source Reader 1
         │                    ├──── Source Reader 2
         │                    ├──── HTTP Server
         │                    ├──── TCP Server
         │                    ├──── Filter Processor
         │                    ├──── HTTP Client Writer
         │                    └──── TCP Client Writer
         │
         ├──── Pipeline 2 ────┬──── Source Reader
         │                    └──── Sink Writers
         │
         └──── HTTP Router (if enabled)

Channel Communication:
Source ──chan──▶ Filter ──chan──▶ Sink
  │                                 │
  └── Non-blocking send ────────────┘
      (drop & count if full)
```

## Configuration Loading

```
Priority Order:
1. CLI Flags ─────────┐
2. Environment Vars ──┼──▶ Merge ──▶ Final Config
3. Config File ───────┤
4. Defaults ──────────┘

Example:
CLI:     --logging.level debug
Env:     LOGWISP_PIPELINES_0_NAME=app
File:    pipelines.toml
Default: buffer_size = 1000
```

## Security Architecture

```
Security Layers:

┌─────────────────────────────────────┐
│         Network Layer               │
├─────────────────────────────────────┤
│ • Rate Limiting (per IP/global)     │
│ • Connection Limits                 │
│ • TLS/SSL (planned)                 │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Authentication Layer           │
├─────────────────────────────────────┤
│ • Basic Auth (planned)              │
│ • Bearer Tokens (planned)           │
│ • IP Whitelisting (planned)         │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Application Layer              │
├─────────────────────────────────────┤
│ • Input Validation                  │
│ • Path Traversal Prevention         │
│ • Resource Limits                   │
└─────────────────────────────────────┘
```