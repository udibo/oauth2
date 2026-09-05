import {
  assert,
  assertEquals,
  assertExists,
  assertMatch,
  assertNotEquals,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { assertSpyCalls, stub } from "@std/testing/mock";

import {
  exportSigningKeyJwk,
  generateSigningKey,
  importSigningKeyJwk,
  signJwt,
  verifyJwt,
} from "../server/signing-keys.ts";
import { runCli } from "./mod.ts";

const decoder = new TextDecoder();

async function spawnCli(
  args: string[],
  permissions: string[] = [],
): Promise<{ code: number; stdout: string; stderr: string }> {
  const { code, stdout, stderr } = await new Deno.Command(Deno.execPath(), {
    args: ["run", "--quiet", "--no-prompt", ...permissions, "mod.ts", ...args],
    cwd: import.meta.dirname,
    stdout: "piped",
    stderr: "piped",
  }).output();
  return {
    code,
    stdout: decoder.decode(stdout),
    stderr: decoder.decode(stderr),
  };
}

describe("oidc keygen", () => {
  it("prints a JWK the OIDC_SIGNING_KEY loader imports and signs with", async () => {
    const { code, stdout } = await spawnCli(["oidc", "keygen"]);
    assertEquals(code, 0);

    const key = await importSigningKeyJwk(JSON.parse(stdout));
    const jwt = await signJwt(key, { sub: "user-1", iss: "https://issuer" });
    const payload = await verifyJwt(jwt, key.publicJwk);
    assertEquals(payload?.sub, "user-1");
  });

  it("prints the JWK as a single env-var-safe line on stdout", async () => {
    const { stdout } = await spawnCli(["oidc", "keygen"]);

    assertEquals(stdout.split("\n").length, 2);
    assertEquals(stdout.at(-1), "\n");
    assertEquals(JSON.stringify(JSON.parse(stdout)), stdout.trimEnd());
  });

  it("emits a kid so the published JWKS keeps it across boots", async () => {
    const { stdout } = await spawnCli(["oidc", "keygen"]);
    const jwk = JSON.parse(stdout);

    assertEquals(typeof jwk.kid, "string");
    assertEquals(jwk.alg, "ES256");
    assertEquals(jwk.crv, "P-256");
    assertExists(jwk.d);
    assertEquals((await importSigningKeyJwk(jwk)).kid, jwk.kid);
  });

  it("keeps operator guidance on stderr, out of the pasted secret", async () => {
    const { stdout, stderr } = await spawnCli(["oidc", "keygen"]);

    assertMatch(stderr, /OIDC_SIGNING_KEY/);
    assertMatch(stderr, /never commit it/);
    const jwk = JSON.parse(stdout);
    assertEquals(stderr.includes(jwk.d), false);
  });

  it("generates a different key on every run", async () => {
    const first = JSON.parse((await spawnCli(["oidc", "keygen"])).stdout);
    const second = JSON.parse((await spawnCli(["oidc", "keygen"])).stdout);

    assertNotEquals(first.kid, second.kid);
    assertNotEquals(first.d, second.d);
  });

  it("runs without any Deno permissions", async () => {
    const { code, stderr } = await spawnCli(["oidc", "keygen"]);

    assertEquals(code, 0);
    assertEquals(stderr.includes("PermissionDenied"), false);
    assertEquals(stderr.includes("Requires"), false);
  });

  it("rejects arguments instead of guessing what they meant", async () => {
    using log = stub(console, "log");
    using error = stub(console, "error");

    assertEquals(await runCli(["oidc", "keygen", "--out", "key.json"]), 1);
    assertSpyCalls(log, 0);
    assertMatch(String(error.calls[0].args[0]), /takes no arguments/);
  });
});

const ADMIN_TOKEN = "test-admin-token";

async function withIdpProcess(
  options: { args: string[]; env: Record<string, string> },
  fn: (context: { url: string; banner: string }) => Promise<void>,
): Promise<void> {
  const child = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--quiet",
      "--no-prompt",
      "--allow-net",
      "--allow-read",
      "--allow-env",
      "mod.ts",
      "idp",
      "dev",
      "--port",
      "0",
      "--admin-token",
      ADMIN_TOKEN,
      ...options.args,
    ],
    cwd: import.meta.dirname,
    env: options.env,
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  const reader = child.stdout.pipeThrough(new TextDecoderStream()).getReader();
  try {
    let banner = "";
    let listening: RegExpMatchArray | null = null;
    while (!listening) {
      const { value, done } = await reader.read();
      if (done) {
        throw new Error(`the server exited before listening:\n${banner}`);
      }
      banner += value;
      listening = banner.match(/Listening on (http:\/\/\S+)/);
    }
    await fn({ url: listening[1], banner });
  } finally {
    child.kill("SIGTERM");
    await child.status;
    await reader.cancel();
    await child.stderr.cancel();
  }
}

describe("idp dev", () => {
  it("serves discovery signed by the key in OIDC_SIGNING_KEY", async () => {
    const key = await generateSigningKey();
    const jwk = await exportSigningKeyJwk(key);

    await withIdpProcess(
      { args: [], env: { OIDC_SIGNING_KEY: JSON.stringify(jwk) } },
      async ({ url, banner }) => {
        const metadata = await (await fetch(
          `${url}/.well-known/openid-configuration`,
        )).json();
        assertEquals(metadata.issuer, url);

        const { keys } = await (await fetch(`${url}/jwks`)).json();
        assertEquals(keys[0].kid, key.kid);
        assertMatch(banner, /DEVELOPMENT AND CI ONLY/);
        assertMatch(banner, /loaded from OIDC_SIGNING_KEY/);
        assertMatch(banner, /Reachable from: this machine only \(loopback\)/);
        assertMatch(banner, new RegExp(`Admin token: ${ADMIN_TOKEN}`));
      },
    );
  });

  it("seeds the users and clients from a config file", async () => {
    const path = await Deno.makeTempFile({ suffix: ".json" });
    try {
      await Deno.writeTextFile(
        path,
        JSON.stringify({
          users: [{ username: "dev", password: "pw" }],
          clients: [{
            id: "web",
            redirectUris: ["http://localhost:4000/cb"],
          }],
        }),
      );

      await withIdpProcess(
        { args: ["--config", path], env: {} },
        async ({ url, banner }) => {
          const state = await (await fetch(`${url}/__admin/state`, {
            headers: { "x-admin-token": ADMIN_TOKEN },
          })).json();
          assertEquals(state.users, [{ id: "dev", username: "dev" }]);
          assertEquals(state.clients[0].id, "web");
          assertEquals(state.clients[0].confidential, false);
          assertMatch(banner, /dev {2}password: pw/);
        },
      );
    } finally {
      await Deno.remove(path);
    }
  });

  it("exits with the config error when the file is malformed", async () => {
    const path = await Deno.makeTempFile({ suffix: ".json" });
    try {
      await Deno.writeTextFile(path, '{ "port": -1 }');
      const { code, stderr } = await spawnCli(
        ["idp", "dev", "--config", path],
        ["--allow-read"],
      );

      assertEquals(code, 1);
      assertMatch(stderr, /config.port must be an integer/);
    } finally {
      await Deno.remove(path);
    }
  });

  it("refuses a non-loopback bind without the unsafe opt-in", async () => {
    const { code, stderr } = await spawnCli(
      ["idp", "dev", "--port", "0", "--hostname", "0.0.0.0"],
      ["--allow-net", "--allow-env"],
    );

    assertEquals(code, 1);
    assertMatch(stderr, /refusing to bind 0\.0\.0\.0/);
    assertMatch(stderr, /--unsafe-remote-access/);
  });

  it("rejects an unknown option instead of ignoring it", async () => {
    using log = stub(console, "log");
    using error = stub(console, "error");

    assertEquals(await runCli(["idp", "dev", "--porta", "9000"]), 1);
    assertSpyCalls(log, 0);
    assertMatch(String(error.calls[0].args[0]), /unknown option "--porta"/);
  });
});

describe("runCli", () => {
  it("prints usage to stderr and fails when no command is given", async () => {
    using log = stub(console, "log");
    using error = stub(console, "error");

    assertEquals(await runCli([]), 1);
    assertSpyCalls(log, 0);
    assertMatch(String(error.calls[0].args[0]), /oidc keygen/);
  });

  it("lists every command in usage", async () => {
    using log = stub(console, "log");

    assertEquals(await runCli(["--help"]), 0);
    const usage = String(log.calls[0].args[0]);
    assert(usage.includes("oidc keygen"));
    assert(usage.includes("idp dev"));
  });

  it("prints usage to stdout on --help", async () => {
    using log = stub(console, "log");
    using error = stub(console, "error");

    assertEquals(await runCli(["--help"]), 0);
    assertSpyCalls(error, 0);
    assertMatch(String(log.calls[0].args[0]), /oidc keygen/);
  });

  it("treats --help after a command as a help request", async () => {
    using log = stub(console, "log");

    assertEquals(await runCli(["oidc", "keygen", "--help"]), 0);
    assertMatch(String(log.calls[0].args[0]), /Usage:/);
  });

  it("fails on an unknown command", async () => {
    using log = stub(console, "log");
    using error = stub(console, "error");

    assertEquals(await runCli(["oidc", "rotate"]), 1);
    assertSpyCalls(log, 0);
    const message = String(error.calls[0].args[0]);
    assertMatch(message, /unknown command "oidc rotate"/);
    assert(message.includes("oidc keygen"));
  });
});
