---
layout: default
title: API Reference
---

# API Reference

## gRPC API

The full protobuf definition is in [`proto/aivisor/v1/aivisor.proto`](../../proto/aivisor/v1/aivisor.proto).

**Design decisions** are documented in [RFC 0001](../rfcs/0001-agent-api.md).

### Core RPCs

| RPC | Description |
|---|---|
| `CreateSandbox` | Create a new sandbox from a template |
| `Exec` | Bidirectional streaming exec (stdin/stdout/stderr) |
| `PauseSandbox` | Freeze a sandbox via cgroup.freeze |
| `ResumeSandbox` | Thaw a frozen sandbox |
| `DestroySandbox` | Tear down and reclaim all resources |
| `InspectSandbox` | Get sandbox state, limits, stats |
| `StreamEvents` | Subscribe to audit events |
| `GrantCapability` | Widen policy at runtime |
| `RevokeCapability` | Narrow policy at runtime |

## SDKs

| SDK | Package | Docs |
|---|---|---|
| Python | `aivisor` | [`sdk/python/`](../../sdk/python/) |
| TypeScript | `@aivisor/sdk` | [`sdk/typescript/`](../../sdk/typescript/) |

### Python Quickstart

```python
from aivisor import Client

client = Client()
with client.sandbox(template="python-agent", timeout="30m") as sb:
    r = sb.run("python3 -c 'print(2+2)'")
    print(r.stdout)  # "4\n"
```

### TypeScript Quickstart

```typescript
import { Client } from '@aivisor/sdk';

const client = new Client();
const sb = await client.createSandbox({ template: 'python-agent' });
const r = await sb.run('python3 -c "print(2+2)"');
console.log(r.stdout); // "4\n"
await sb.destroy();
```
