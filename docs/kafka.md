# Kafka Design

## Purpose

This document defines the Kafka contract for the Mango Parental Control Service.

 uses Kafka for service discovery and lifecycle only.

## Lifecycle And Discovery

The service shall follow the same lifecycle pattern used by `owsub`.

Topic:

- `service_events`

Published events:

- `join`
- `keep-alive`
- `leave`

Message shape:

```json
{
 "event": "join",
 "id": 1008,
 "type": "parentalcontrol",
 "publicEndPoint": "https://openwifi.wlan.local:16008",
 "privateEndPoint": "https://parentalcontrol.wlan.local:17008",
 "key": "sha256(publicEndPoint)",
 "version": "dev"
}
```

Rules:

- `type` shall be `parentalcontrol`
- `key` shall be the SHA-256 hex digest of `SYSTEM_URI_PUBLIC`
- `owsub` shall discover the service through this topic and call the private API over HTTP

## Publishing Rules

- lifecycle events shall be published by `ow-common-mods/servicediscovery`
- `owsub` shall use Kafka only for discovery, not as the request path for parental-control API operations
