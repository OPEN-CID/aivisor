"""Python SDK client for the AIVisor daemon.

Talks to ``aivisord`` over its Unix socket using newline-delimited JSON.

**Daemon status**: ``aivisord`` does not serve this protocol yet — its
listener is ``TODO(phase4)`` (see ``crates/aivisord/src/daemon.rs``). Every
call here will therefore fail to connect against a current build. The client
is complete; it is the daemon side that is outstanding. Stated here rather
than left for a user to discover as a confusing connection error.
"""

from __future__ import annotations

import json
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional


class ProtocolError(RuntimeError):
    """The daemon answered, but not with something this client can use."""


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int


class SandboxHandle:
    """A running sandbox. Destroyed on context manager exit."""

    def __init__(self, client: Client, sandbox_id: str):
        self._client = client
        self._id = sandbox_id

    @property
    def id(self) -> str:
        return self._id

    def run(self, command: str, timeout: Optional[int] = None) -> ExecResult:
        """Run a command in the sandbox and wait for completion."""
        payload = {
            "cmd": ["/bin/sh", "-c", command],
            "timeout": timeout,
        }
        resp = self._client._request("exec", self._id, payload)
        return ExecResult(
            stdout=resp.get("stdout", ""),
            stderr=resp.get("stderr", ""),
            exit_code=resp.get("exit_code", -1),
        )

    def write_file(self, path: str, content: str) -> None:
        """Write a file to the sandbox workspace."""
        self.run(f"cat > {path} << 'AIVEOF'\n{content}\nAIVEOF")

    @contextmanager
    def turn(self) -> Iterator[None]:
        """Context manager for a tracked turn (enables dirty tracking)."""
        self._client._request("begin_turn", self._id, {})
        try:
            yield
        finally:
            self._client._request("end_turn", self._id, {})

    def snapshot(self) -> str:
        """Create a workspace snapshot. Returns snapshot ID.

        Raises if the daemon does not return one: handing back ``""`` would
        let a caller store a snapshot id that addresses nothing and only
        discover it at restore time.
        """
        resp = self._client._request("snapshot", self._id, {})
        snapshot_id = resp.get("snapshot_id")
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ProtocolError(
                "daemon did not return a snapshot_id for sandbox "
                f"{self._id}; refusing to return an id that names no snapshot"
            )
        return snapshot_id

    def __enter__(self) -> "SandboxHandle":
        return self

    def __exit__(self, *args) -> None:
        self._client._request("destroy", self._id, {})


class Client:
    """AIVisor daemon client over Unix socket."""

    def __init__(
        self,
        socket_path: str = "/run/aivisor/aivisord.sock",
        timeout: float = 30.0,
    ):
        self._socket_path = socket_path
        self._timeout = timeout

    def _connect(self) -> socket.socket:
        """Open a connection to the daemon.

        Separate from :meth:`_request` so the framing and error handling can
        be exercised on platforms whose Python has no ``AF_UNIX`` (CPython
        does not expose it on Windows) by overriding just this method. The
        default — and the only transport aivisord will offer — is a Unix
        socket.
        """
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout)
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        return sock

    def _request(self, action: str, sandbox_id: str, payload: dict) -> dict:
        """Send a JSON request over the Unix socket."""
        msg = {
            "action": action,
            "sandbox_id": sandbox_id,
            **payload,
        }
        data = json.dumps(msg).encode() + b"\n"

        try:
            sock = self._connect()
        except FileNotFoundError as e:
            raise ConnectionError(
                f"AIVisor daemon not found at {self._socket_path}. "
                "Is aivisord running?"
            ) from e

        try:
            sock.sendall(data)

            response = b""
            while b"\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    # Connection closed before a complete frame arrived. This
                    # is a failure, not an empty success: falling through to
                    # json.loads(b"") would surface as an opaque decode error.
                    raise ProtocolError(
                        f"aivisord closed the connection after {len(response)} "
                        f"byte(s) without sending a complete response to "
                        f"'{action}'"
                    )
                response += chunk

            line = response.split(b"\n", 1)[0]
            try:
                decoded = json.loads(line.decode())
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise ProtocolError(
                    f"unparseable response from aivisord: {line!r}"
                ) from e
            if not isinstance(decoded, dict):
                raise ProtocolError(
                    f"expected a JSON object from aivisord, got {type(decoded).__name__}"
                )
            return decoded
        finally:
            sock.close()

    @contextmanager
    def sandbox(
        self,
        template: str = "base",
        timeout: str = "30m",
    ) -> Iterator[SandboxHandle]:
        """Create a sandbox and return a handle. Destroys on exit."""
        resp = self._request("create", "", {
            "template": template,
            "timeout": timeout,
        })
        sandbox_id = resp.get("sandbox_id")
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise ProtocolError(
                "daemon did not return a sandbox_id; refusing to yield a "
                "handle that addresses no sandbox"
            )
        handle = SandboxHandle(self, sandbox_id)
        try:
            yield handle
        finally:
            self._request("destroy", sandbox_id, {})
