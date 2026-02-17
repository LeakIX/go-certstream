# go-certstream

A high-performance, low-memory alternative for the CaliDog's [certstream-server](https://github.com/CaliDog/certstream-server). Built for LeakIX, released OSS.

## Architecture

- **Atomic COW Broadcaster**: Uses Copy-On-Write with `atomic.Value` to achieve lock-free message distribution across hundreds of concurrent WebSocket clients.
- **Self-Healing Backoff**: Implements an 'Appeasement' heuristic. It ramps up 50ms on `429 Too Many Requests` and decays by 1ms for every successfully processed certificate. It finds the log's speed limit automatically.
- **Staggered Workers**: Distributes network load by jittering the start time of the 60+ CT log workers.
- **Graceful Orchestration**: Fully context-aware. Shuts down in milliseconds, not seconds.

## Performance
- **RAM**: ~25-50MB (vs 200MB+ for BEAM-based alternatives).
- **CPU**: Minimal, using single-pass JSON serialization for all broadcast clients.
- **Throughput**: Capable of handling the full global CT log firehose on a single core.

## Installation

```bash
go install github.com/LeakIX/go-certstream/cmd/certstream@master
```

## Usage

### Environment Variables
- `WEBSOCKET_LISTEN`: Address to bind the server (default: `:8080`).
- `CUSTOM_LOG_LIST`: URL to a custom CT log list JSON (default: Google's V3 list).

### Running
```bash
WEBSOCKET_LISTEN=":9999" certstream
```

## WebSocket API
The output is 100% compatible with the CaliDog/Certstream JSON format.

### Connection
```bash
websocat ws://localhost:8080
```

### Format
```json
{
  "message_type": "certificate_update",
  "data": {
    "leaf_cert": {
      "subject": { "CN": "example.com" },
      "extensions": { "subjectAltName": "example.com, www.example.com" }
    },
    "source": { "url": "https://ct.googleapis.com/logs/xenon2025/", "name": "" }
  }
}
```

## Tactical Notes
- **Slow Consumers**: If a WebSocket client's buffer (default: 256) fills up, the broadcaster will drop frames for that specific client to maintain system-wide real-time integrity.