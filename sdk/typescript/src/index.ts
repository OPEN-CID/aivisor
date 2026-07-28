/**
 * AIVisor TypeScript SDK
 *
 * Lightweight sandbox runtime for AI agents.
 */

import { connect, Socket } from "net";

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
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
      stdout: resp.stdout ?? "",
      stderr: resp.stderr ?? "",
      exitCode: resp.exit_code ?? -1,
    };
  }

  async destroy(): Promise<void> {
    await this.client.request("destroy", this.sandboxId, {});
  }
}

export class Client {
  constructor(private socketPath = "/run/aivisor/aivisord.sock") {}

  async request(
    action: string,
    sandboxId: string,
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const sock = connect(this.socketPath, () => {
        const msg = JSON.stringify({ action, sandbox_id: sandboxId, ...payload }) + "\n";
        sock.write(msg);
      });

      let data = "";
      sock.on("data", (chunk) => {
        data += chunk.toString();
        if (data.includes("\n")) {
          sock.end();
          try {
            resolve(JSON.parse(data.trim()));
          } catch (e) {
            reject(new Error(`Invalid response: ${data}`));
          }
        }
      });

      sock.on("error", reject);
      sock.setTimeout(30000, () => {
        sock.destroy();
        reject(new Error("Request timeout"));
      });
    });
  }

  async createSandbox(template = "base", timeout = "30m"): Promise<SandboxHandle> {
    const resp = await this.request("create", "", { template, timeout });
    const sandboxId = (resp.sandbox_id ?? "") as string;
    return new SandboxHandle(this, sandboxId);
  }
}
