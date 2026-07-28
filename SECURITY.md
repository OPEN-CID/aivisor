# Security Policy for AIVisor

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | Pre-release        |

## What AIVisor Protects

AIVisor protects the host kernel and other co-located sandboxes from a hostile
AI agent running inside a sandbox. It does **not** protect the agent from the
host, the host from a kernel 0-day, or co-located sandboxes from each other in
the presence of CPU microarchitectural side channels.

**Full threat model:** `docs/threat-model.md`

## Reporting a Vulnerability

AIVisor is a security-critical sandbox runtime. Please report vulnerabilities
privately.

- **Email:** security@aivisor.dev
- **GPG key:** [available at ...]

We will acknowledge receipt within 48 hours and provide an initial assessment
within 5 business days.

### Disclosure Policy

- We will work with the reporter to validate and reproduce the finding.
- A fix will be developed and tested.
- We commit to a **90-day coordinated disclosure window** from the date the
  fix is released.
- Vulnerabilities will be credited in release notes unless the reporter
  requests anonymity.
- Critical vulnerabilities (sandbox escape, host compromise, credential leak)
  may be disclosed earlier with a mitigation available.

## Scope

This security policy covers the AIVisor runtime (`aivisord`, `aivisor-cli`,
`aivisor-runtime`, `aivisor-bpf`, `aivisor-broker`, `aivisor-policy`,
`aivisor-snapshot`) and the core SDKs.

The following are **out of scope**:
- The AI model or agent code running *inside* the sandbox
- Kernel vulnerabilities that predate AIVisor's supported kernel matrix
- Side-channel attacks requiring local access to the same hardware

## Hall of Fame

We maintain a security researcher hall of fame for verified reports.
To be added, submit a valid report through the private disclosure channel.
