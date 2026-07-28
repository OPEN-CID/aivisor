"""Python SDK client for AIVisor daemon."""

from __future__ import annotations

import json
import os
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional


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
        """Create a workspace snapshot. Returns snapshot ID."""
        resp = self._client._request("snapshot", self._id, {})
        return resp.get("snapshot_id", "")

    def __enter__(self) -> "SandboxHandle":
        return self

    def __exit__(self, *args) -> None:
        self._client._request("destroy", self._id, {})


class Client:
    """AIVisor daemon client over Unix socket."""

    def __init__(self, socket_path: str = "/run/aivisor/aivisord.sock"):
        self._socket_path = socket_path

    def _request(self, action: str, sandbox_id: str, payload: dict) -> dict:
        """Send a JSON request over the Unix socket."""
        msg = {
            "action": action,
            "sandbox_id": sandbox_id,
            **payload,
        }
        data = json.dumps(msg).encode() + b"\n"

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(30)
            sock.connect(self._socket_path)
            sock.sendall(data)

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\n" in response:
                    break

            return json.loads(response.decode().strip())
        except FileNotFoundError:
            raise ConnectionError(
                f"AIVisor daemon not found at {self._socket_path}. "
                "Is aivisord running?"
            )
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
        sandbox_id = resp.get("sandbox_id", "")
        handle = SandboxHandle(self, sandbox_id)
        try:
            yield handle
        finally:
            self._request("destroy", sandbox_id, {})
