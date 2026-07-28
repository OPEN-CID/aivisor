---
layout: default
title: RFC 0001 — Agent API
status: draft
date: 2026-07-27
---

# RFC 0001 — Agent API

## Summary

The gRPC API defined in `proto/aivisor/v1/aivisor.proto` is the primary
interface for creating and managing AIVisor sandboxes. This RFC documents
the design decisions.

## Key Decisions

1. **Unix socket as primary transport.** Peer-credential authentication is
   simpler and more secure than TLS for node-local communication.

2. **mTLS for remote access.** Required for multi-node deployments. SPIFFE
   SVIDs authenticate both client and server.

3. **Streaming for Exec.** Bidirectional streams allow stdin/stdout/stderr
   multiplexing and proper flow control.

4. **Idempotency keys on all mutating RPCs.** Replayed requests return the
   original result, not an error.

5. **Server-side backpressure for StreamEvents.** The kernel ring buffer
   consumer must never be blocked by a slow gRPC client.
