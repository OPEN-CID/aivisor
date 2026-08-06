"""Unit tests for the AIVisor Python client.

These run against a stand-in Unix-socket server, not a real ``aivisord``
(whose listener is still ``TODO(phase4)``). The client is what is under test:
each case pins the wire framing, and — more importantly — that every way the
daemon can fail to answer properly surfaces as an exception rather than as a
plausible-looking empty result.

Stdlib ``unittest`` on purpose: the SDK has no runtime dependencies and CI
should not need to install a test framework to gate it.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest
from typing import Callable, Optional

from aivisor import Client, ProtocolError, SandboxHandle


HAVE_AF_UNIX = hasattr(socket, "AF_UNIX")


class StubDaemon:
    """A one-connection-at-a-time newline-JSON server.

    Binds a Unix socket where the platform has one — the transport aivisord
    will actually use, and what CI exercises — and falls back to a loopback
    TCP socket on platforms whose Python lacks ``AF_UNIX`` (Windows). The
    fallback pairs with :class:`_TcpClient` below so the client's framing and
    error handling stay under test everywhere, rather than the whole suite
    silently skipping on a developer workstation.
    """

    def __init__(self, handler: Callable[[dict], Optional[str]]):
        self._handler = handler
        self.seen: list[dict] = []
        self._dir: Optional[str] = None

        if HAVE_AF_UNIX:
            self._dir = tempfile.mkdtemp(prefix="aivisor-test-")
            self.path = os.path.join(self._dir, "d.sock")
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.bind(self.path)
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.bind(("127.0.0.1", 0))
            self.path = "%s:%d" % self._sock.getsockname()

        self._sock.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                if b"\n" not in buf:
                    continue
                request = json.loads(buf.split(b"\n", 1)[0].decode())
                self.seen.append(request)
                reply = self._handler(request)
                if reply is not None:
                    conn.sendall(reply.encode())

    def close(self) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=5)
        if self._dir is not None:
            try:
                os.unlink(self.path)
                os.rmdir(self._dir)
            except OSError:
                pass


class _TcpClient(Client):
    """`Client` over loopback TCP, for platforms without ``AF_UNIX``.

    Overrides connection setup only — the framing, parsing and fail-closed
    checks under test are all inherited unchanged.
    """

    def _connect(self) -> socket.socket:
        host, port = self._socket_path.rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(self._timeout)
            sock.connect((host, int(port)))
        except BaseException:
            sock.close()
            raise
        return sock


def client_for(path: str) -> Client:
    return Client(path) if HAVE_AF_UNIX else _TcpClient(path)


class ClientTests(unittest.TestCase):
    def serve(self, handler: Callable[[dict], Optional[str]]) -> StubDaemon:
        daemon = StubDaemon(handler)
        self.addCleanup(daemon.close)
        return daemon

    def test_sandbox_framing_and_handle(self) -> None:
        daemon = self.serve(lambda _req: json.dumps({"sandbox_id": "sbx-1"}) + "\n")

        with client_for(daemon.path).sandbox(template="base", timeout="10m") as sb:
            self.assertEqual(sb.id, "sbx-1")

        self.assertEqual(
            daemon.seen[0],
            {
                "action": "create",
                "sandbox_id": "",
                "template": "base",
                "timeout": "10m",
            },
        )
        # The context manager must destroy on exit.
        self.assertEqual(daemon.seen[-1]["action"], "destroy")
        self.assertEqual(daemon.seen[-1]["sandbox_id"], "sbx-1")

    def test_run_maps_exec_result(self) -> None:
        daemon = self.serve(
            lambda _req: json.dumps(
                {"stdout": "hi", "stderr": "warn", "exit_code": 0}
            )
            + "\n"
        )

        result = SandboxHandle(client_for(daemon.path), "sbx-1").run("echo hi")

        self.assertEqual(result.stdout, "hi")
        self.assertEqual(result.stderr, "warn")
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(daemon.seen[0]["cmd"], ["/bin/sh", "-c", "echo hi"])

    def test_missing_exit_code_is_not_reported_as_success(self) -> None:
        daemon = self.serve(lambda _req: json.dumps({"stdout": "out"}) + "\n")

        result = SandboxHandle(client_for(daemon.path), "sbx-1").run("true")

        self.assertEqual(result.exit_code, -1)

    def test_incomplete_frame_raises(self) -> None:
        daemon = self.serve(lambda _req: None)

        with self.assertRaises(ProtocolError):
            client_for(daemon.path)._request("create", "", {})

    def test_unparseable_reply_raises(self) -> None:
        daemon = self.serve(lambda _req: "not json\n")

        with self.assertRaises(ProtocolError):
            client_for(daemon.path)._request("create", "", {})

    def test_non_object_reply_raises(self) -> None:
        daemon = self.serve(lambda _req: json.dumps([1, 2, 3]) + "\n")

        with self.assertRaises(ProtocolError):
            client_for(daemon.path)._request("create", "", {})

    def test_missing_sandbox_id_raises(self) -> None:
        daemon = self.serve(lambda _req: json.dumps({}) + "\n")

        with self.assertRaises(ProtocolError):
            with client_for(daemon.path).sandbox():
                self.fail("sandbox() must not yield a handle without an id")

    def test_missing_snapshot_id_raises(self) -> None:
        daemon = self.serve(lambda _req: json.dumps({}) + "\n")

        with self.assertRaises(ProtocolError):
            SandboxHandle(client_for(daemon.path), "sbx-1").snapshot()

    @unittest.skipUnless(
        HAVE_AF_UNIX, "exercises the Unix-socket-missing path specifically"
    )
    def test_absent_daemon_raises_connection_error(self) -> None:
        missing = os.path.join(tempfile.mkdtemp(prefix="aivisor-test-"), "nope.sock")

        with self.assertRaises(ConnectionError):
            Client(missing)._request("create", "", {})


if __name__ == "__main__":
    unittest.main()
