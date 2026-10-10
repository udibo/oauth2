/**
 * The runtime half of the npm smoke test: imports every subpath of the
 * installed `@udibo/oauth2` package under real Node module resolution and
 * probes one known export per subpath, so a subpath that type-checks but
 * cannot load (a broken specifier, a missing dependency) fails loudly.
 *
 * The subpath list is read from the installed package's export map, so a
 * subpath added to the package is smoke-tested automatically.
 *
 * @module
 */
import { readFile } from "node:fs/promises";
import { Hono } from "hono";

const KNOWN_EXPORTS = {
  "./server": "BasicScope",
  "./server/authorization": "AuthorizationServer",
  "./server/resource": "ResourceServer",
  "./server/public-suffix": "isPublicSuffix",
  "./client": "BffClient",
  "./identity": "MemoryOtpStore",
  "./identity/external": "MemoryDiscoveryCache",
  "./identity/mfa": "MemoryMfaStore",
  "./identity/migration": "parsePhc",
  "./hono/resource-server": "HonoResourceServer",
  "./hono/authorization-server": "HonoAuthorizationServer",
  "./hono/bff": "EncryptedCookieSessionStore",
  "./hono/bff/testing": "createTestSession",
  "./hono/identity": "honoIdentityRoutes",
  "./hono/log": "requestLogger",
  "./react": "OAuth2Provider",
  "./react/components": "SignInForm",
  "./react/testing": "MockOAuth2Provider",
  "./testing": "createFakeTenant",
  "./testing/contract": "runLockoutStoreContractTests",
  "./crypto": "sha256Hash",
  "./url": "safeReturnTo",
};

const packageJson = JSON.parse(
  await readFile(
    new URL("./node_modules/@udibo/oauth2/package.json", import.meta.url),
    "utf-8",
  ),
);

const failures = [];
const subpaths = Object.keys(packageJson.exports).filter(
  (subpath) => subpath !== "./package.json",
);

for (const subpath of subpaths) {
  const specifier = `@udibo/oauth2${subpath.slice(1)}`;
  let module;
  try {
    module = await import(specifier);
  } catch (error) {
    failures.push(`${specifier} failed to import: ${error}`);
    continue;
  }
  const known = KNOWN_EXPORTS[subpath];
  if (known === undefined) {
    failures.push(
      `${subpath} has no KNOWN_EXPORTS entry in scripts/npm-smoke/main.mjs; ` +
        `add one for the new subpath`,
    );
  } else if (module[known] === undefined) {
    failures.push(`${specifier} did not export ${known}`);
  }
}

const { sha256Hash } = await import("@udibo/oauth2/crypto");
const digest = await sha256Hash("npm-smoke");
if (typeof digest !== "string" || digest.length === 0) {
  failures.push(`sha256Hash returned ${JSON.stringify(digest)}`);
}

const { isPublicSuffix } = await import("@udibo/oauth2/server/public-suffix");
if (isPublicSuffix("com") !== true) {
  failures.push('isPublicSuffix("com") was not true');
}

const { BffClient } = await import("@udibo/oauth2/client");
const { DirectClient } = await import("@udibo/oauth2/client");
const { HonoBff } = await import("@udibo/oauth2/hono/bff");
for (const options of [
  { forwardedParams: ["__proto__"] },
  { extraParams: { ["__proto__"]: "configured" } },
]) {
  const client = new DirectClient({
    clientId: "node-smoke",
    redirectUri: "https://app.example.com/auth/callback",
    endpoints: {
      authorization: "https://issuer.example.com/authorize",
      token: "https://issuer.example.com/token",
    },
  });
  const bff = new HonoBff({ client, ...options });
  const app = new Hono().route("/auth", bff.routes());
  const response = await app.request(
    "https://app.example.com/auth/login?__proto__=configured",
  );
  await response.body?.cancel();
  const location = response.headers.get("location");
  if (
    response.status !== 302 ||
    !location ||
    new URL(location).searchParams.get("__proto__") !== "configured"
  ) {
    failures.push(
      "HonoBff dropped an explicitly configured __proto__ parameter",
    );
  }
}
const { redactedRequestTarget } = await import("@udibo/oauth2/hono/log");
if (
  redactedRequestTarget("https://app.example.com/auth/callback?code=secret") !==
  "/auth/callback?code=[redacted]"
) {
  failures.push("request target did not redact the callback code");
}
if (typeof new BffClient().subscribe !== "function") {
  failures.push("BffClient did not construct with a subscribe method");
}

if (failures.length > 0) {
  console.error(`npm smoke (runtime): ${failures.length} failure(s)`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}

console.log(
  `npm smoke (runtime): imported ${subpaths.length} subpaths on Node ${process.version}`,
);
