"""AIVisor Python SDK — lightweight sandbox runtime for AI agents.

Usage:
    from aivisor import Client

    client = Client()                          # unix socket by default
    with client.sandbox(template="python-agent", timeout="30m") as sb:
        r = sb.run("python3 -c 'print(2+2)'")
        print(r.stdout)                        # "4\\n"
"""

from .client import Client, ExecResult, ProtocolError, SandboxHandle

__all__ = ["Client", "ExecResult", "ProtocolError", "SandboxHandle"]
