/**
 * The Node runtime half of the npm smoke test: imports every Node-supported
 * subpath of the installed `@udibo/oauth2` artifact under real Node module
 * resolution and probes one known export per subpath, so a subpath that
 * only type-checks but cannot load (a broken specifier, a Deno global, a
 * dependency Node cannot resolve) fails loudly.
 *
 * The subpath list is read from the installed package's export map rather
 * than written out here, so a subpath added to the artifact is smoke-tested
 * automatically; `UNVERIFIED_ON_NODE` mirrors the README runtime table's
 * `/testing` row, the one group whose Node support stays an untested claim.
 *
 * @module
 */
import { readFile } from "node:fs/promises";

export const UNVERIFIED_ON_NODE = ["./testing", "./testing/contract"];

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
const subpaths = Object.keys(packageJson.exports)
  .filter((subpath) => !UNVERIFIED_ON_NODE.includes(subpath));

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
      `${subpath} has no KNOWN_EXPORTS entry in npm-smoke-consumer/main.mjs; ` +
        `add one (new subpath?) or add it to UNVERIFIED_ON_NODE with a ` +
        `README runtime-table row to match`,
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
