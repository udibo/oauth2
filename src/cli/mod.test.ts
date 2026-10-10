import { spawn } from "node:child_process";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { assert, describe, expect, it, vi } from "vitest";
import {
  exportSigningKeyJwk,
  generateSigningKey,
  importSigningKeyJwk,
  signJwt,
  verifyJwt,
} from "../server/signing-keys.ts";
import { runCli } from "./mod.ts";

const ENTRYPOINT = fileURLToPath(new URL("./bin.ts", import.meta.url));
const NODE_ARGUMENTS = ["--disable-warning=ExperimentalWarning", ENTRYPOINT];

function cliEnvironment(
  overrides: Record<string, string> = {},
): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, ...overrides };
}

function spawnCli(
  args: string[],
  options: { cwd?: string } = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...NODE_ARGUMENTS, ...args], {
      cwd: options.cwd,
      env: cliEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk) => (stderr += chunk));
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("oidc keygen", () => {
  it("prints a JWK the OIDC_SIGNING_KEY loader imports and signs with", async () => {
    const { code, stdout } = await spawnCli(["oidc", "keygen"]);
    expect(code).toStrictEqual(0);

    const key = await importSigningKeyJwk(JSON.parse(stdout));
    const jwt = await signJwt(key, { sub: "user-1", iss: "https://issuer" });
    const payload = await verifyJwt(jwt, key.publicJwk);
    expect(payload?.sub).toStrictEqual("user-1");
  });

  it("prints the JWK as a single env-var-safe line on stdout", async () => {
    const { stdout } = await spawnCli(["oidc", "keygen"]);

    expect(stdout.split("\n").length).toStrictEqual(2);
    expect(stdout.at(-1)).toStrictEqual("\n");
    expect(JSON.stringify(JSON.parse(stdout))).toStrictEqual(stdout.trimEnd());
  });

  it("emits a kid so the published JWKS keeps it across boots", async () => {
    const { stdout } = await spawnCli(["oidc", "keygen"]);
    const jwk = JSON.parse(stdout);

    expect(typeof jwk.kid).toStrictEqual("string");
    expect(jwk.alg).toStrictEqual("ES256");
    expect(jwk.crv).toStrictEqual("P-256");
    assert.exists(jwk.d);
    expect((await importSigningKeyJwk(jwk)).kid).toStrictEqual(jwk.kid);
  });

  it("keeps operator guidance on stderr, out of the pasted secret", async () => {
    const { stdout, stderr } = await spawnCli(["oidc", "keygen"]);

    expect(stderr).toMatch(/OIDC_SIGNING_KEY/);
    expect(stderr).toMatch(/never commit it/);
    const jwk = JSON.parse(stdout);
    expect(stderr.includes(jwk.d)).toStrictEqual(false);
  });

  it("generates a different key on every run", async () => {
    const first = JSON.parse((await spawnCli(["oidc", "keygen"])).stdout);
    const second = JSON.parse((await spawnCli(["oidc", "keygen"])).stdout);

    expect(first.kid).not.toStrictEqual(second.kid);
    expect(first.d).not.toStrictEqual(second.d);
  });

  it("writes nothing to disk", async () => {
    const directory = await mkdtemp(join(tmpdir(), "oauth2-cli-cwd-"));
    try {
      const { code } = await spawnCli(["oidc", "keygen"], { cwd: directory });

      expect(code).toStrictEqual(0);
      expect(await readdir(directory)).toStrictEqual([]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects arguments instead of guessing what they meant", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});
    using error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["oidc", "keygen", "--out", "key.json"])).toStrictEqual(
      1,
    );
    expect(log).toHaveBeenCalledTimes(0);
    expect(String(error.mock.calls[0]?.[0])).toMatch(/takes no arguments/);
  });
});

const ADMIN_TOKEN = "test-admin-token";

async function withConfigFile(
  contents: string,
  fn: (path: string) => Promise<void>,
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "oauth2-cli-config-"));
  try {
    const path = join(directory, "idp.json");
    await writeFile(path, contents);
    await fn(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function withIdpProcess(
  options: { args: string[]; env: Record<string, string> },
  fn: (context: { url: string; banner: string }) => Promise<void>,
): Promise<void> {
  const child = spawn(
    process.execPath,
    [
      ...NODE_ARGUMENTS,
      "idp",
      "dev",
      "--port",
      "0",
      "--admin-token",
      ADMIN_TOKEN,
      ...options.args,
    ],
    { env: cliEnvironment(options.env), stdio: ["ignore", "pipe", "pipe"] },
  );
  child.stderr.resume();
  const exited = new Promise<void>((resolve) => {
    child.once("close", () => resolve());
  });
  try {
    const banner = await new Promise<string>((resolve, reject) => {
      let output = "";
      child.stdout.setEncoding("utf8").on("data", (chunk) => {
        output += chunk;
        if (/Listening on (http:\/\/\S+)/.test(output)) resolve(output);
      });
      child.once("error", reject);
      child.once("close", () => {
        reject(new Error(`the server exited before listening:\n${output}`));
      });
    });
    const url = banner.match(/Listening on (http:\/\/\S+)/)![1];
    await fn({ url, banner });
  } finally {
    child.kill("SIGTERM");
    await exited;
  }
}

describe("idp dev", () => {
  it("serves discovery signed by the key in OIDC_SIGNING_KEY", async () => {
    const key = await generateSigningKey();
    const jwk = await exportSigningKeyJwk(key);

    await withIdpProcess(
      { args: [], env: { OIDC_SIGNING_KEY: JSON.stringify(jwk) } },
      async ({ url, banner }) => {
        const metadata = await (
          await fetch(`${url}/.well-known/openid-configuration`)
        ).json();
        expect(metadata.issuer).toStrictEqual(url);

        const { keys } = await (await fetch(`${url}/jwks`)).json();
        expect(keys[0].kid).toStrictEqual(key.kid);
        expect(banner).toMatch(/DEVELOPMENT AND CI ONLY/);
        expect(banner).toMatch(/loaded from OIDC_SIGNING_KEY/);
        expect(banner).toMatch(
          /Reachable from: this machine only \(loopback\)/,
        );
        expect(banner).toMatch(new RegExp(`Admin token: ${ADMIN_TOKEN}`));
      },
    );
  });

  it("seeds the users and clients from a config file", async () => {
    await withConfigFile(
      JSON.stringify({
        users: [{ username: "dev", password: "pw" }],
        clients: [{ id: "web", redirectUris: ["http://localhost:4000/cb"] }],
      }),
      (path) =>
        withIdpProcess(
          { args: ["--config", path], env: {} },
          async ({ url, banner }) => {
            const state = await (
              await fetch(`${url}/__admin/state`, {
                headers: { "x-admin-token": ADMIN_TOKEN },
              })
            ).json();
            expect(state.users).toStrictEqual([{ id: "dev", username: "dev" }]);
            expect(state.clients[0].id).toStrictEqual("web");
            expect(state.clients[0].confidential).toStrictEqual(false);
            expect(banner).toMatch(/dev {2}password: pw/);
          },
        ),
    );
  });

  it("exits with the config error when the file is malformed", async () => {
    await withConfigFile('{ "port": -1 }', async (path) => {
      const { code, stderr } = await spawnCli(["idp", "dev", "--config", path]);

      expect(code).toStrictEqual(1);
      expect(stderr).toMatch(/config.port must be an integer/);
    });
  });

  it("refuses a non-loopback bind without the unsafe opt-in", async () => {
    const { code, stderr } = await spawnCli([
      "idp",
      "dev",
      "--port",
      "0",
      "--hostname",
      "0.0.0.0",
    ]);

    expect(code).toStrictEqual(1);
    expect(stderr).toMatch(/refusing to bind 0\.0\.0\.0/);
    expect(stderr).toMatch(/--unsafe-remote-access/);
  });

  it("rejects an unknown option instead of ignoring it", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});
    using error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["idp", "dev", "--porta", "9000"])).toStrictEqual(1);
    expect(log).toHaveBeenCalledTimes(0);
    expect(String(error.mock.calls[0]?.[0])).toMatch(
      /unknown option "--porta"/,
    );
  });
});

describe("runCli", () => {
  it("prints usage to stderr and fails when no command is given", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});
    using error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli([])).toStrictEqual(1);
    expect(log).toHaveBeenCalledTimes(0);
    expect(String(error.mock.calls[0]?.[0])).toMatch(/oidc keygen/);
  });

  it("lists every command in usage", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});

    expect(await runCli(["--help"])).toStrictEqual(0);
    const usage = String(log.mock.calls[0]?.[0]);
    assert(usage.includes("oidc keygen"));
    assert(usage.includes("idp dev"));
  });

  it("prints usage to stdout on --help", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});
    using error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["--help"])).toStrictEqual(0);
    expect(error).toHaveBeenCalledTimes(0);
    expect(String(log.mock.calls[0]?.[0])).toMatch(/oidc keygen/);
  });

  it("treats --help after a command as a help request", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});

    expect(await runCli(["oidc", "keygen", "--help"])).toStrictEqual(0);
    expect(String(log.mock.calls[0]?.[0])).toMatch(/Usage:/);
  });

  it("fails on an unknown command", async () => {
    using log = vi.spyOn(console, "log").mockImplementation(() => {});
    using error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["oidc", "rotate"])).toStrictEqual(1);
    expect(log).toHaveBeenCalledTimes(0);
    const message = String(error.mock.calls[0]?.[0]);
    expect(message).toMatch(/unknown command "oidc rotate"/);
    assert(message.includes("oidc keygen"));
  });
});
