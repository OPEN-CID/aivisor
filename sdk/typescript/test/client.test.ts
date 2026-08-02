import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { AivisorError, Client, SandboxHandle } from "../src/index.js";

/**
 * A stand-in for `aivisord`'s (still unimplemented) socket listener. The
 * client is the thing under test: these cases pin the wire framing and,
 * more importantly, that every way the daemon can fail to answer properly
 * surfaces as a rejection rather than a plausible-looking empty result.
 */
function listen(
  handler: (request: Record<string, unknown>) => string | null,
): Promise<{ server: Server; path: string }> {
  // Windows has no AF_UNIX for node:net; a named pipe is the equivalent
  // local endpoint and exercises the same client code path.
  const path =
    process.platform === "win32"
      ? `\\\\.\\pipe\\aivisor-test-${randomUUID()}`
      : join(tmpdir(), `aivisor-test-${randomUUID()}.sock`);

  const server = createServer((sock) => {
    let buf = "";
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const newline = buf.indexOf("\n");
      if (newline === -1) return;
      const request = JSON.parse(buf.slice(0, newline)) as Record<
        string,
        unknown
      >;
      const reply = handler(request);
      if (reply === null) {
        sock.end(); // close without ever sending a complete frame
      } else {
        sock.write(reply);
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(path, () => resolve({ server, path }));
  });
}

let open: Server | undefined;

afterEach(async () => {
  if (open) {
    await new Promise<void>((resolve) => open!.close(() => resolve()));
    open = undefined;
  }
});

describe("Client", () => {
  it("sends action/sandbox_id framing and parses the reply", async () => {
    let seen: Record<string, unknown> | undefined;
    const { server, path } = await listen((req) => {
      seen = req;
      return JSON.stringify({ sandbox_id: "sbx-123" }) + "\n";
    });
    open = server;

    const handle = await new Client(path).createSandbox("base", "10m");

    expect(handle.sandboxId).toBe("sbx-123");
    expect(seen).toEqual({
      action: "create",
      sandbox_id: "",
      template: "base",
      timeout: "10m",
    });
  });

  it("maps stdout/stderr/exit_code onto ExecResult", async () => {
    let seen: Record<string, unknown> | undefined;
    const { server, path } = await listen((req) => {
      seen = req;
      return (
        JSON.stringify({ stdout: "hi", stderr: "warn", exit_code: 0 }) + "\n"
      );
    });
    open = server;

    const result = await new SandboxHandle(new Client(path), "sbx-1").run(
      "echo hi",
    );

    expect(result).toEqual({ stdout: "hi", stderr: "warn", exitCode: 0 });
    expect(seen).toMatchObject({
      action: "exec",
      sandbox_id: "sbx-1",
      cmd: ["/bin/sh", "-c", "echo hi"],
    });
  });

  it("reports a missing exit_code as -1, never as success", async () => {
    const { server, path } = await listen(
      () => JSON.stringify({ stdout: "out" }) + "\n",
    );
    open = server;

    const result = await new SandboxHandle(new Client(path), "sbx-1").run(
      "true",
    );

    expect(result.exitCode).toBe(-1);
    expect(result.stdout).toBe("out");
  });

  it("reports a non-numeric exit_code as -1", async () => {
    const { server, path } = await listen(
      () => JSON.stringify({ exit_code: "0" }) + "\n",
    );
    open = server;

    const result = await new SandboxHandle(new Client(path), "sbx-1").run(
      "true",
    );

    expect(result.exitCode).toBe(-1);
  });

  it("rejects when the daemon closes without a complete frame", async () => {
    const { server, path } = await listen(() => null);
    open = server;

    await expect(new Client(path).createSandbox()).rejects.toBeInstanceOf(
      AivisorError,
    );
  });

  it("rejects on an unparseable reply", async () => {
    const { server, path } = await listen(() => "this is not json\n");
    open = server;

    await expect(new Client(path).createSandbox()).rejects.toThrow(
      /invalid response/,
    );
  });

  it("refuses a handle when the daemon returns no sandbox_id", async () => {
    const { server, path } = await listen(() => JSON.stringify({}) + "\n");
    open = server;

    await expect(new Client(path).createSandbox()).rejects.toThrow(
      /did not return a sandbox_id/,
    );
  });

  it("rejects when nothing is listening", async () => {
    const path =
      process.platform === "win32"
        ? `\\\\.\\pipe\\aivisor-absent-${randomUUID()}`
        : join(tmpdir(), `aivisor-absent-${randomUUID()}.sock`);

    await expect(new Client(path).createSandbox()).rejects.toThrow(
      /cannot reach aivisord/,
    );
  });
});
