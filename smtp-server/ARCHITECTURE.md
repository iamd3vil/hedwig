# Hedwig SMTP Server Architecture

## Overview

Hedwig is a high-performance, async SMTP server written in Rust that provides email relay functionality with advanced features including DKIM signing, retry mechanisms, and flexible storage backends. The server is designed with a modular architecture that separates concerns and provides extensibility.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SMTP Server                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Listener  │    │   Listener  │    │   Listener  │         │
│  │ (Plain/TLS) │    │ (Plain/TLS) │    │ (Plain/TLS) │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                 SMTP Callbacks                              │ │
│  │  • Authentication • Domain Filtering • Rate Limiting       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                   Storage Layer                             │ │
│  │          ┌─────────────┐    ┌─────────────┐                │ │
│  │          │   Queued    │    │  Deferred   │                │ │
│  │          │   Emails    │    │   Emails    │                │ │
│  │          └─────────────┘    └─────────────┘                │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                 Processing Workers                          │ │
│  │  ┌─────────────┐              ┌─────────────┐              │ │
│  │  │   Worker    │              │  Deferred   │              │ │
│  │  │  (Sender)   │              │   Worker    │              │ │
│  │  └─────────────┘              └─────────────┘              │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                             │                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Outbound SMTP Pool                             │ │
│  │     ┌─────────┐    ┌─────────┐    ┌─────────┐              │ │
│  │     │ MX-1    │    │ MX-2    │    │ MX-N    │              │ │
│  │     │ Pool    │    │ Pool    │    │ Pool    │              │ │
│  │     └─────────┘    └─────────┘    └─────────┘              │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Main Server (`main.rs`)

The entry point that orchestrates the entire system:

- **Configuration Loading**: Loads TOML configuration files
- **TLS Setup**: Configures TLS certificates for secure connections
- **Multi-Listener Support**: Supports multiple listening addresses with different TLS configurations
- **Worker Initialization**: Sets up background processing workers
- **DKIM Key Management**: Handles RSA and Ed25519 key generation

#### Key Responsibilities:
- Server lifecycle management
- TLS certificate loading and validation
- Channel setup for worker communication
- Storage backend initialization

### 2. SMTP Callbacks (`callbacks.rs`)

Implements the SMTP protocol state machine and business logic:

```
┌─────────────────────────────────────────────────────────────┐
│                    SMTP Protocol Flow                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client Connect → EHLO → AUTH → MAIL FROM → RCPT TO → DATA │
│       │            │      │        │          │        │   │
│       ▼            ▼      ▼        ▼          ▼        ▼   │
│  ┌─────────┐ ┌─────────┐ ┌─────┐ ┌─────────┐ ┌─────┐ ┌───┐ │
│  │ Connect │ │  EHLO   │ │AUTH │ │MAIL FROM│ │RCPT │ │DATA│ │
│  │Callback │ │Callback │ │Check│ │ Filter  │ │Filter│ │Save│ │
│  └─────────┘ └─────────┘ └─────┘ └─────────┘ └─────┘ └───┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Features:
- **Domain Filtering**: Allow/deny lists for sender and recipient domains
- **Authentication**: Configurable SMTP AUTH with credential validation
- **MX Record Caching**: Efficient DNS lookups with TTL-based expiration
- **Email Validation**: Path and domain extraction with validation

### 3. Worker System (`worker/`)

#### Main Worker (`worker/mod.rs`)

The core email processing engine:

```
┌─────────────────────────────────────────────────────────────┐
│                   Email Processing Flow                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Job Queue → Parse Email → DKIM Sign → MX Lookup → Send    │
│      │           │            │           │          │     │
│      ▼           ▼            ▼           ▼          ▼     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────┐   │
│  │Receive  │ │ Parse   │ │  DKIM   │ │   MX    │ │Send │   │
│  │Job from │ │Email    │ │ Signing │ │ Record  │ │via  │   │
│  │Channel  │ │Body     │ │Process  │ │ Lookup  │ │SMTP │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────┘   │
│                                                    │        │
│                                        Success ────┘        │
│                                                             │
│                                        Failure             │
│                                           │                 │
│                                           ▼                 │
│                                    ┌─────────────┐          │
│                                    │   Retry     │          │
│                                    │ Evaluation  │          │
│                                    └─────────────┘          │
│                                           │                 │
│                                  ┌────────┴────────┐        │
│                                  ▼                 ▼        │
│                            ┌─────────┐      ┌─────────┐     │
│                            │ Defer   │      │ Bounce  │     │
│                            │ Email   │      │ Email   │     │
│                            └─────────┘      └─────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Features:**
- **DKIM Signing**: Supports both RSA and Ed25519 signatures
- **BCC Header Removal**: Strips BCC headers before sending
- **Multi-Recipient Support**: Handles To, CC, and BCC recipients
- **Error Classification**: Distinguishes between temporary and permanent failures
- **MX Record Processing**: Attempts delivery via all MX records in preference order

#### Deferred Worker (`worker/deferred_worker.rs`)

Manages retry logic for failed email deliveries:

```
┌─────────────────────────────────────────────────────────────┐
│                  Retry Logic Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Scan Deferred → Check Retry Time → Evaluate Attempts      │
│       │               │                    │                │
│       ▼               ▼                    ▼                │
│  ┌─────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ List    │    │ Time-based  │    │ Attempt     │         │
│  │Deferred │    │ Filtering   │    │ Threshold   │         │
│  │ Emails  │    │ (Next Time) │    │ Check       │         │
│  └─────────┘    └─────────────┘    └─────────────┘         │
│                        │                    │               │
│                 Ready? │             Max Attempts?          │
│                        ▼                    ▼               │
│                 ┌─────────────┐      ┌─────────────┐       │
│                 │   Requeue   │      │ Permanent   │       │
│                 │   Email     │      │  Failure    │       │
│                 └─────────────┘      └─────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Retry Strategy:**
- **Exponential Backoff**: `delay = initial_delay * 2^attempts`
- **Maximum Delay Cap**: Prevents excessive delays
- **Configurable Max Retries**: Default 5 attempts
- **Permanent Failure Handling**: Moves to bounced status after max attempts

#### Connection Pool (`worker/pool.rs`)

Efficient SMTP connection management:

```
┌─────────────────────────────────────────────────────────────┐
│                Connection Pool Architecture                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                 Pool Manager                            │ │
│  │                                                         │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │ │
│  │  │   Domain    │  │   Domain    │  │   Domain    │    │ │
│  │  │   Pool 1    │  │   Pool 2    │  │   Pool N    │    │ │
│  │  │             │  │             │  │             │    │ │
│  │  │ ┌─────────┐ │  │ ┌─────────┐ │  │ ┌─────────┐ │    │ │
│  │  │ │ Conn 1  │ │  │ │ Conn 1  │ │  │ │ Conn 1  │ │    │ │
│  │  │ │ Conn 2  │ │  │ │ Conn 2  │ │  │ │ Conn 2  │ │    │ │
│  │  │ │   ...   │ │  │ │   ...   │ │  │ │   ...   │ │    │ │
│  │  │ │ Conn N  │ │  │ │ Conn N  │ │  │ │ Conn N  │ │    │ │
│  │  │ └─────────┘ │  │ └─────────┘ │  │ └─────────┘ │    │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Pool Features:**
- **Per-Domain Pooling**: Separate pools for each destination domain
- **TLS Configuration**: Supports both TLS and plain connections
- **Connection Limits**: Configurable min/max connection counts
- **Timeout Handling**: Configurable connection timeouts
- **Local Mode**: Supports non-TLS connections for testing

## Data Flow

### Inbound Email Processing

```
┌─────────────────────────────────────────────────────────────┐
│                 Inbound Email Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Client Connection                                       │
│     ┌─────────────┐                                         │
│     │   Client    │                                         │
│     │ Connection  │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  2. SMTP Protocol Negotiation                              │
│     ┌─────────────┐                                         │
│     │    EHLO     │                                         │
│     │    AUTH     │                                         │
│     │ MAIL FROM   │                                         │
│     │  RCPT TO    │                                         │
│     │    DATA     │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  3. Email Storage                                          │
│     ┌─────────────┐                                         │
│     │   Store     │                                         │
│     │  Email in   │                                         │
│     │   Queue     │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  4. Job Creation                                           │
│     ┌─────────────┐                                         │
│     │   Create    │                                         │
│     │Processing   │                                         │
│     │    Job      │                                         │
│     └─────────────┘                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Outbound Email Processing

```
┌─────────────────────────────────────────────────────────────┐
│                Outbound Email Flow                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Job Processing                                          │
│     ┌─────────────┐                                         │
│     │   Worker    │                                         │
│     │ Receives    │                                         │
│     │    Job      │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  2. Email Preparation                                      │
│     ┌─────────────┐                                         │
│     │Parse Email  │                                         │
│     │Remove BCC   │                                         │
│     │Sign w/DKIM  │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  3. Recipient Processing                                   │
│     ┌─────────────┐                                         │
│     │Extract All  │                                         │
│     │Recipients   │                                         │
│     │(To/CC/BCC)  │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  4. MX Resolution                                          │
│     ┌─────────────┐                                         │
│     │ DNS MX      │                                         │
│     │ Lookup      │                                         │
│     │ (Cached)    │                                         │
│     └─────────────┘                                         │
│            │                                                │
│            ▼                                                │
│  5. SMTP Delivery                                          │
│     ┌─────────────┐                                         │
│     │   Send      │                                         │
│     │   via       │                                         │
│     │   Pool      │                                         │
│     └─────────────┘                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Configuration Architecture

The server uses a hierarchical TOML configuration system:

```toml
[server]
max_retries = 5

[[server.listeners]]
addr = "127.0.0.1:25"

[server.listeners.tls]
cert_path = "/path/to/cert.pem"
key_path = "/path/to/key.pem"

[server.auth]
username = "user"
password = "pass"

[server.dkim]
domain = "example.com"
selector = "default"
private_key = "/path/to/dkim.key"
key_type = "rsa"  # or "ed25519"

[storage]
storage_type = "fs"
base_path = "/var/lib/hedwig"

[log]
level = "info"
format = "text"  # or "json"
```

## Storage Architecture

The storage layer provides an abstraction over different backends:

```
┌─────────────────────────────────────────────────────────────┐
│                   Storage Layer                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                Storage Trait                            │ │
│  │  • get(id, status) -> Email                            │ │
│  │  • put(email, status) -> Result                        │ │
│  │  • mv(id, from_status, to_status) -> Result            │ │
│  │  • delete(id, status) -> Result                        │ │
│  │  • list(status) -> Stream<Email>                       │ │
│  │  • get_meta/put_meta/delete_meta -> Metadata           │ │
│  └─────────────────────────────────────────────────────────┘ │
│                             │                               │
│                             ▼                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                File System Storage                      │ │
│  │                                                         │ │
│  │  Directory Structure:                                   │ │
│  │  /base_path/                                           │ │
│  │    ├── queued/                                         │ │
│  │    ├── deferred/                                       │ │
│  │    ├── bounced/                                        │ │
│  │    └── meta/                                           │ │
│  │                                                         │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Security Features

### 1. TLS Support
- **Inbound TLS**: Configurable per-listener
- **Outbound TLS**: Required for external delivery
- **Certificate Management**: File-based certificate loading

### 2. Authentication
- **SMTP AUTH**: Optional username/password authentication
- **Credential Validation**: Constant-time comparison to prevent timing attacks

### 3. DKIM Signing
- **Algorithm Support**: RSA (2048-bit) and Ed25519
- **Header Selection**: Configurable header signing
- **Key Management**: File-based private key storage

### 4. Domain Filtering
- **Allow Lists**: Permitted sender/recipient domains
- **Deny Lists**: Blocked sender/recipient domains
- **Flexible Matching**: Supports domain and subdomain matching

## Performance Characteristics

### Concurrency Model
- **Async/Await**: Tokio-based async runtime
- **Multi-Listener**: Concurrent handling of multiple listening addresses
- **Connection Pooling**: Efficient outbound connection reuse
- **Channel-Based**: Lock-free job distribution

### Caching Strategy
- **MX Record Caching**: TTL-based DNS result caching
- **Connection Pooling**: Per-domain connection pools
- **In-Memory Caching**: Moka-based caching for frequently accessed data

### Scalability Features
- **Horizontal Scaling**: Stateless worker design
- **Resource Limits**: Configurable pool sizes and timeouts
- **Backpressure Handling**: Bounded channels prevent memory exhaustion

## Error Handling and Resilience

### Retry Strategy
```
Attempt 1: Immediate
Attempt 2: 60 seconds
Attempt 3: 120 seconds (2 minutes)
Attempt 4: 240 seconds (4 minutes)
Attempt 5: 480 seconds (8 minutes)
Max Delay: 24 hours
```

### Error Classification
- **Temporary Errors**: 4XX codes, connection failures
- **Permanent Errors**: 5XX codes (except retryable ones)
- **Timeout Handling**: Configurable SMTP timeouts

### Failure Modes
- **Bounce Handling**: Permanent failures moved to bounced status
- **Graceful Degradation**: Continues processing other emails on individual failures
- **Circuit Breaking**: Connection pool prevents cascading failures

## Monitoring and Observability

### Logging
- **Structured Logging**: Tracing-based structured logs
- **Log Levels**: Configurable verbosity
- **Format Options**: Text or JSON output
- **Contextual Information**: Message IDs, email addresses, error details

### Metrics (Extensible)
- Email processing rates
- Queue depths
- Retry counts
- Connection pool utilization
- DKIM signing performance

## Deployment Considerations

### System Requirements
- **Runtime**: Tokio async runtime
- **Dependencies**: Minimal system dependencies
- **Permissions**: File system access for storage and key files

### Configuration Management
- **File-Based**: TOML configuration files
- **Environment Variables**: Log level override via `HEDWIG_LOG_LEVEL`
- **Runtime Commands**: DKIM key generation utility

### Operations
- **Graceful Shutdown**: Proper cleanup of resources
- **Queue Recovery**: Automatic processing of queued emails on startup
- **Key Rotation**: File-based DKIM key management

## Extension Points

### Storage Backends
The storage trait allows for additional backends:
- Database-backed storage (PostgreSQL, MySQL)
- Cloud storage (S3, Azure Blob)
- Distributed storage systems

### Authentication Methods
- LDAP integration
- OAuth2 support
- Multi-factor authentication

### Filtering Extensions
- Content-based filtering
- Rate limiting per domain
- Integration with external reputation services

### Monitoring Integration
- Prometheus metrics
- Health check endpoints
- Performance telemetry

This architecture provides a solid foundation for a production-ready SMTP server with room for future enhancements and scaling requirements.