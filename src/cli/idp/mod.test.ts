import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  exportSigningKeyJwk,
  generateSigningKey,
} from "../../server/signing-keys.ts";
import { runCli } from "../mod.ts";

const ADMIN_TOKEN = "in-process-admin-token";

interface RunningIdp {
  url: string;
  banner: string;
  stderr(): string;
  stop(): Promise<number>;
}

const running: RunningIdp[] = [];

async function startIdp(
  args: string[],
  environment: Record<string, string> = {},
): Promise<RunningIdp> {
  for (const [name, value] of Object.entries(environment)) {
    vi.stubEnv(name, value);
  }
  const log = vi.spyOn(console, "log").mockImplementation(() => {});
  const error = vi.spyOn(console, "error").mockImplementation(() => {});
  const controller = new AbortController();
  const result = runCli(["idp", "dev", "--port", "0", ...args], {
    signal: controller.signal,
  });
  const failed = result.then((code) => {
    throw new Error(
      `idp dev exited with ${code} before listening:\n${error.mock.calls.join("\n")}`,
    );
  });
  const banner = await Promise.race([
    vi.waitFor(() => {
      const text = log.mock.calls.map((call) => call.join(" ")).join("\n");
      if (!/Listening on http:\/\/\S+/.test(text)) throw new Error("waiting");
      return text;
    }),
    failed,
  ]);
  const idp: RunningIdp = {
    url: banner.match(/Listening on (http:\/\/\S+)/)![1]!,
    banner,
    stderr: () => error.mock.calls.map((call) => call.join(" ")).join("\n"),
    async stop() {
      controller.abort();
      return await result;
    },
  };
  running.push(idp);
  return idp;
}

async function withConfigFile(
  config: unknown,
  fn: (path: string) => Promise<void>,
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "oauth2-idp-mod-"));
  try {
    const path = join(directory, "idp.json");
    await writeFile(path, JSON.stringify(config));
    await fn(path);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

afterEach(async () => {
  await Promise.all(running.splice(0).map((idp) => idp.stop()));
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("idp dev", () => {
  it("signs with the key in OIDC_SIGNING_KEY and says where it came from", async () => {
    const key = await generateSigningKey();
    const jwk = await exportSigningKeyJwk(key);
    const idp = await startIdp(["--admin-token", ADMIN_TOKEN], {
      OIDC_SIGNING_KEY: JSON.stringify(jwk),
    });

    const { keys } = await (await fetch(`${idp.url}/jwks`)).json();
    expect(keys[0].kid).toBe(key.kid);
    expect(idp.banner).toContain(
      `Signing key: loaded from OIDC_SIGNING_KEY (kid ${key.kid})`,
    );
    expect(idp.banner).toContain("DEVELOPMENT AND CI ONLY");
    expect(idp.banner).toContain(
      "Reachable from: this machine only (loopback)",
    );
    expect(idp.banner).toContain(`Admin token: ${ADMIN_TOKEN}`);
    expect(idp.stderr()).not.toContain("No OIDC_SIGNING_KEY");
    expect(await idp.stop()).toBe(0);
  });

  it("loads the signing key from the config file when the variable is unset", async () => {
    const key = await generateSigningKey();
    const jwk = await exportSigningKeyJwk(key);
    await withConfigFile({ signingKey: jwk }, async (path) => {
      const idp = await startIdp(["--config", path]);

      expect(idp.banner).toContain(
        `Signing key: loaded from the config file (kid ${key.kid})`,
      );
      const { keys } = await (await fetch(`${idp.url}/jwks`)).json();
      expect(keys[0].kid).toBe(key.kid);
    });
  });

  it("lets OIDC_SIGNING_KEY win over the config file", async () => {
    const fromConfig = await exportSigningKeyJwk(await generateSigningKey());
    const fromEnvironment = await generateSigningKey();
    await withConfigFile({ signingKey: fromConfig }, async (path) => {
      const idp = await startIdp(["--config", path], {
        OIDC_SIGNING_KEY: JSON.stringify(
          await exportSigningKeyJwk(fromEnvironment),
        ),
      });

      const { keys } = await (await fetch(`${idp.url}/jwks`)).json();
      expect(keys[0].kid).toBe(fromEnvironment.kid);
    });
  });

  it("warns that a generated key changes on every restart", async () => {
    vi.stubEnv("OIDC_SIGNING_KEY", "");
    const idp = await startIdp([]);

    expect(idp.banner).toMatch(/Signing key: generated \(kid \S+\)/);
    expect(idp.stderr()).toContain("No OIDC_SIGNING_KEY");
    expect(idp.stderr()).toContain("udibo-oauth2 oidc keygen");
  });

  it("rejects an OIDC_SIGNING_KEY that is not JSON before listening", async () => {
    vi.stubEnv("OIDC_SIGNING_KEY", "not json");
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["idp", "dev", "--port", "0"])).toBe(1);
    expect(String(error.mock.calls[0]?.[0])).toContain(
      "OIDC_SIGNING_KEY is not valid JSON",
    );
  });

  it("takes the admin token from IDP_ADMIN_TOKEN when no flag is given", async () => {
    const idp = await startIdp([], { IDP_ADMIN_TOKEN: "from-environment" });

    expect(idp.banner).toContain("Admin token: from-environment");
    const rejected = await fetch(`${idp.url}/__admin/state`);
    expect(rejected.status).toBe(401);
    const accepted = await fetch(`${idp.url}/__admin/state`, {
      headers: { "x-admin-token": "from-environment" },
    });
    expect(accepted.status).toBe(200);
  });

  it("lets the --admin-token flag win over IDP_ADMIN_TOKEN", async () => {
    const idp = await startIdp(["--admin-token", ADMIN_TOKEN], {
      IDP_ADMIN_TOKEN: "from-environment",
    });

    expect(idp.banner).toContain(`Admin token: ${ADMIN_TOKEN}`);
  });

  it("seeds users and clients from the config file and lists them", async () => {
    await withConfigFile(
      {
        users: [{ username: "dev", password: "pw" }],
        clients: [
          { id: "web", redirectUris: ["http://localhost:4000/cb"] },
          {
            id: "api",
            secret: "shh",
            grants: ["client_credentials"],
            redirectUris: [],
          },
        ],
      },
      async (path) => {
        const idp = await startIdp([
          "--config",
          path,
          "--admin-token",
          ADMIN_TOKEN,
        ]);

        expect(idp.banner).toMatch(/dev {2}password: pw {2}sub: dev/);
        expect(idp.banner).toContain("web  public client");
        expect(idp.banner).toContain("api  secret: shh");
        expect(idp.banner).toContain("redirect URIs: (none)");
        const state = await (
          await fetch(`${idp.url}/__admin/state`, {
            headers: { "x-admin-token": ADMIN_TOKEN },
          })
        ).json();
        expect(state.users).toStrictEqual([{ id: "dev", username: "dev" }]);
      },
    );
  });

  it("lists no users or clients when the config seeds none", async () => {
    await withConfigFile({ users: [], clients: [] }, async (path) => {
      const idp = await startIdp(["--config", path]);

      expect(idp.banner).toContain("Users:\n  (none)");
      expect(idp.banner).toContain("Clients:\n  (none)");
    });
  });

  it("pins the issuer with --issuer and says so", async () => {
    const idp = await startIdp(["--issuer", "https://idp.test"]);

    expect(idp.banner).toContain("Issuer: https://idp.test\n");
    const metadata = await (
      await fetch(`${idp.url}/.well-known/openid-configuration`)
    ).json();
    expect(metadata.issuer).toBe("https://idp.test");
  });

  it("derives the issuer from the bind address and points at --issuer", async () => {
    const idp = await startIdp([]);

    expect(idp.banner).toContain(
      `Issuer: ${idp.url} (derived from the bind address; pin it with --issuer)`,
    );
  });

  it("accepts --flag=value as well as --flag value", async () => {
    const idp = await startIdp([
      "--hostname=127.0.0.1",
      "--admin-token=equals-form",
    ]);

    expect(idp.banner).toContain("Admin token: equals-form");
    expect(idp.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it("announces a prompted consent screen", async () => {
    await withConfigFile({ consent: "prompt" }, async (path) => {
      const idp = await startIdp(["--config", path]);

      expect(idp.banner).toContain("Consent: prompted");
    });
  });

  it("states that consent is granted automatically by default", async () => {
    const idp = await startIdp([]);

    expect(idp.banner).toContain("Consent: granted automatically");
  });

  it("binds a non-loopback address only with --unsafe-remote-access, and warns", async () => {
    const idp = await startIdp([
      "--hostname",
      "0.0.0.0",
      "--unsafe-remote-access",
    ]);

    expect(idp.banner).toContain(
      "Reachable from: ANY HOST THAT CAN REACH 0.0.0.0",
    );
    expect(idp.stderr()).toContain("WARNING: bound to 0.0.0.0");
    expect(idp.stderr()).toContain("not loopback");
  });

  it("refuses a non-loopback address without the opt-in", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(
      await runCli(["idp", "dev", "--port", "0", "--hostname", "0.0.0.0"]),
    ).toBe(1);
    expect(String(error.mock.calls[0]?.[0])).toMatch(
      /refusing to bind 0\.0\.0\.0/,
    );
  });

  it.each([
    [["--port", "70000"], "--port must be an integer between 0 and 65535"],
    [["--port", "abc"], "--port must be an integer between 0 and 65535"],
    [["--port", "1.5"], "--port must be an integer between 0 and 65535"],
    [["--port"], "--port requires a value"],
    [["--port="], "--port requires a value"],
    [["--config"], "--config requires a value"],
    [
      ["--unsafe-remote-access=yes"],
      'unknown option "--unsafe-remote-access=yes"',
    ],
    [["--bogus"], 'unknown option "--bogus"'],
  ])("rejects %j with %s", async (args, message) => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(await runCli(["idp", "dev", ...args])).toBe(1);
    expect(String(error.mock.calls[0]?.[0])).toContain(message);
  });

  it("reports a config file that cannot be read", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    expect(
      await runCli([
        "idp",
        "dev",
        "--config",
        join(tmpdir(), "oauth2-missing.json"),
      ]),
    ).toBe(1);
    expect(String(error.mock.calls[0]?.[0])).toContain("cannot read config");
  });

  it("stops serving and resolves with 0 once its signal aborts", async () => {
    const idp = await startIdp([]);

    expect(await idp.stop()).toBe(0);
    await expect(fetch(`${idp.url}/jwks`)).rejects.toThrow("fetch failed");
  });

  it("starts nothing when its signal is already aborted", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const controller = new AbortController();
    controller.abort();

    expect(
      await runCli(["idp", "dev", "--port", "0"], {
        signal: controller.signal,
      }),
    ).toBe(0);
  });
});
