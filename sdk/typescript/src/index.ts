/**
 * AIVisor TypeScript SDK.
 *
 * Talks to `aivisord` over its Unix socket using newline-delimited JSON.
 *
 * **Daemon status**: `aivisord` does not serve this protocol yet — its
 * listener is `TODO(phase4)` (see `crates/aivisord/src/daemon.rs`). Every
 * call here will therefore fail to connect against a current build. The
 * client is complete and tested against a stand-in server; it is the daemon
 * side that is outstanding. This is stated here rather than left for a user
 * to discover as a confusing ECONNREFUSED.
 */

import { connect } from "node:net";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/** A decoded daemon reply. Field types are not trusted until narrowed. */
export type DaemonResponse = Record<string, unknown>;

/** Thrown when the daemon cannot be reached or answers unintelligibly. */
export class AivisorError extends Error {
  constructor(message: string, cause?: unknown) {
    // ES2022 `cause` rather than a own-property shadow of Error.cause, so
    // the underlying socket error survives in stack traces and logs.
    super(message, cause === undefined ? undefined : { cause });
    this.name = "AivisorError";
  }
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export class SandboxHandle {
  constructor(
    private client: Client,
    readonly sandboxId: string,
  ) {}

  async run(command: string, timeout?: number): Promise<ExecResult> {
    const resp = await this.client.request("exec", this.sandboxId, {
      cmd: ["/bin/sh", "-c", command],
      timeout,
    });
    return {
      stdout: asString(resp.stdout, ""),
      stderr: asString(resp.stderr, ""),
      // -1 rather than 0 on a missing/!numeric exit_code: a reply we cannot
      // read must never be reported to the caller as "the command succeeded".
      exitCode: asNumber(resp.exit_code, -1),
    };
  }

  async destroy(): Promise<void> {
    await this.client.request("destroy", this.sandboxId, {});
  }
}

export class Client {
  constructor(
    private socketPath = "/run/aivisor/aivisord.sock",
    private timeoutMs = 30_000,
  ) {}

  async request(
    action: string,
    sandboxId: string,
    payload: Record<string, unknown>,
  ): Promise<DaemonResponse> {
    return new Promise<DaemonResponse>((resolve, reject) => {
      // Guard against a socket that both errors and times out, or delivers a
      // second newline-terminated frame: the promise must settle exactly once
      // and the socket must always be torn down.
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        sock.destroy();
        fn();
      };

      const sock = connect(this.socketPath, () => {
        sock.write(
          JSON.stringify({ action, sandbox_id: sandboxId, ...payload }) + "\n",
        );
      });

      let data = "";
      sock.on("data", (chunk: Buffer) => {
        data += chunk.toString("utf8");
        const newline = data.indexOf("\n");
        if (newline === -1) return;
        const line = data.slice(0, newline);
        finish(() => {
          try {
            resolve(JSON.parse(line) as DaemonResponse);
          } catch (e) {
            reject(new AivisorError(`invalid response from daemon: ${line}`, e));
          }
        });
      });

      sock.on("error", (e) => {
        finish(() =>
          reject(
            new AivisorError(
              `cannot reach aivisord at ${this.socketPath}: ${e.message}`,
              e,
            ),
          ),
        );
      });

      // A daemon that closes the connection without ever sending a complete
      // frame is a failure, not an empty success.
      sock.on("close", () => {
        finish(() =>
          reject(
            new AivisorError(
              `aivisord closed the connection before sending a complete response (got ${data.length} byte(s))`,
            ),
          ),
        );
      });

      sock.setTimeout(this.timeoutMs, () => {
        finish(() =>
          reject(new AivisorError(`request timed out after ${this.timeoutMs}ms`)),
        );
      });
    });
  }

  async createSandbox(
    template = "base",
    timeout = "30m",
  ): Promise<SandboxHandle> {
    const resp = await this.request("create", "", { template, timeout });
    const sandboxId = asString(resp.sandbox_id, "");
    if (sandboxId === "") {
      throw new AivisorError(
        "daemon did not return a sandbox_id; refusing to hand back a handle that addresses no sandbox",
      );
    }
    return new SandboxHandle(this, sandboxId);
  }
}
