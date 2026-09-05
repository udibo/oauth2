/**
 * The `idp dev` command: runs the development identity provider from a config
 * file (or the built-in demo config) and prints what it seeded.
 *
 * @module
 */

import {
  generateSigningKey,
  importSigningKeyJwk,
  type SigningKey,
} from "../../server/signing-keys.ts";

import {
  defaultDevIdpConfig,
  type DevIdpConfig,
  loadDevIdpConfig,
} from "./config.ts";
import {
  ADMIN_TOKEN_HEADER,
  isLoopbackHostname,
  startDevIdentityProvider,
} from "./server.ts";

const SIGNING_KEY_VARIABLE = "OIDC_SIGNING_KEY";
const ADMIN_TOKEN_VARIABLE = "IDP_ADMIN_TOKEN";

interface IdpDevArgs {
  configPath?: string;
  port?: number;
  hostname?: string;
  issuer?: string;
  adminToken?: string;
  allowRemoteAccess?: boolean;
}

const VALUE_FLAGS = [
  "--config",
  "--port",
  "--hostname",
  "--issuer",
  "--admin-token",
];
const BOOLEAN_FLAGS = ["--unsafe-remote-access"];

function parseIdpDevArgs(args: string[]): IdpDevArgs {
  const parsed: IdpDevArgs = {};
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    const separator = argument.indexOf("=");
    const flag = separator === -1 ? argument : argument.slice(0, separator);
    if (BOOLEAN_FLAGS.includes(flag) && separator === -1) {
      parsed.allowRemoteAccess = true;
      continue;
    }
    if (!VALUE_FLAGS.includes(flag)) {
      throw new Error(
        `unknown option "${argument}" (expected one of: ${
          [...VALUE_FLAGS, ...BOOLEAN_FLAGS].join(", ")
        })`,
      );
    }
    const value = separator === -1
      ? args[++index]
      : argument.slice(separator + 1);
    if (value === undefined || value.length === 0) {
      throw new Error(`${flag} requires a value`);
    }
    if (flag === "--config") parsed.configPath = value;
    if (flag === "--hostname") parsed.hostname = value;
    if (flag === "--issuer") parsed.issuer = value;
    if (flag === "--admin-token") parsed.adminToken = value;
    if (flag === "--port") {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new Error(`--port must be an integer between 0 and 65535`);
      }
      parsed.port = port;
    }
  }
  return parsed;
}

function readVariable(name: string): string | undefined {
  try {
    return Deno.env.get(name) || undefined;
  } catch {
    return undefined;
  }
}

async function resolveSigningKey(
  config: DevIdpConfig,
): Promise<{ key: SigningKey; source: string }> {
  const fromEnvironment = readVariable(SIGNING_KEY_VARIABLE);
  if (fromEnvironment) {
    let jwk: unknown;
    try {
      jwk = JSON.parse(fromEnvironment);
    } catch {
      throw new Error(`${SIGNING_KEY_VARIABLE} is not valid JSON`);
    }
    return {
      key: await importSigningKeyJwk(jwk as JsonWebKey),
      source: SIGNING_KEY_VARIABLE,
    };
  }
  if (config.signingKey) {
    return {
      key: await importSigningKeyJwk(config.signingKey),
      source: "the config file",
    };
  }
  return { key: await generateSigningKey(), source: "" };
}

function describeSeed(config: DevIdpConfig): string[] {
  const lines = ["Users:"];
  if (config.users.length === 0) lines.push("  (none)");
  for (const user of config.users) {
    lines.push(
      `  ${user.username}  password: ${user.password}  sub: ${user.id}`,
    );
  }
  lines.push("", "Clients:");
  if (config.clients.length === 0) lines.push("  (none)");
  for (const client of config.clients) {
    lines.push(
      `  ${client.id}  ${
        client.secret ? `secret: ${client.secret}` : "public client"
      }`,
      `    grants: ${client.grants.join(", ")}`,
      `    redirect URIs: ${client.redirectUris.join(", ") || "(none)"}`,
    );
  }
  return lines;
}

/**
 * Runs the development identity provider until the process is stopped.
 *
 * Accepts `--config <path>`, `--port <number>`, `--hostname <host>`,
 * `--issuer <url>`, `--admin-token <token>`, and `--unsafe-remote-access`;
 * flags win over the config file, which wins over the built-in demo config.
 * `IDP_ADMIN_TOKEN` supplies the admin token when the flag is absent.
 *
 * @throws {Error} When an option or the config file is invalid, or when the
 * bind address is not loopback and `--unsafe-remote-access` was not passed.
 */
export async function idpDev(args: string[]): Promise<void> {
  const options = parseIdpDevArgs(args);
  const config = options.configPath
    ? await loadDevIdpConfig(options.configPath)
    : defaultDevIdpConfig();
  if (options.port !== undefined) config.port = options.port;
  if (options.hostname !== undefined) config.hostname = options.hostname;
  if (options.issuer !== undefined) config.issuer = options.issuer;

  const { key, source } = await resolveSigningKey(config);
  const idp = await startDevIdentityProvider({
    config,
    signingKey: key,
    adminToken: options.adminToken ?? readVariable(ADMIN_TOKEN_VARIABLE),
    allowRemoteAccess: options.allowRemoteAccess,
  });
  const loopback = isLoopbackHostname(idp.hostname);

  console.log([
    "@udibo/oauth2 development identity provider",
    "",
    "  DEVELOPMENT AND CI ONLY. State is in memory and the /__admin/",
    "  endpoints mint tokens for any seeded user without their password.",
    "  Never expose this server to a network you do not control.",
    "",
    `Listening on ${idp.url}`,
    `Reachable from: ${
      loopback
        ? "this machine only (loopback)"
        : `ANY HOST THAT CAN REACH ${idp.hostname}:${idp.port} — remote access was enabled explicitly`
    }`,
    `Issuer: ${idp.issuer}${
      config.issuer
        ? ""
        : " (derived from the bind address; pin it with --issuer)"
    }`,
    `Discovery: ${idp.url}/.well-known/openid-configuration`,
    `JWKS: ${idp.url}/jwks`,
    `Signing key: ${
      source
        ? `loaded from ${source} (kid ${key.kid})`
        : `generated (kid ${key.kid})`
    }`,
    `Consent: ${
      config.consent === "prompt" ? "prompted" : "granted automatically"
    }`,
    "",
    `Admin token: ${idp.adminToken}`,
    `  Send it as the ${ADMIN_TOKEN_HEADER} header on every /__admin/ request.`,
    `  Set ${ADMIN_TOKEN_VARIABLE} or --admin-token to choose it yourself.`,
    "",
    ...describeSeed(config),
  ].join("\n"));

  if (!loopback) {
    console.error(
      `\nWARNING: bound to ${idp.hostname}, which is not loopback. Anyone who ` +
        `can reach this port and read the admin token can mint tokens for any ` +
        `seeded user. Only do this on a network you control, such as a CI ` +
        `job's private network.`,
    );
  }

  if (!source) {
    console.error(
      `\nNo ${SIGNING_KEY_VARIABLE} and no "signingKey" in the config: this ` +
        `key exists only for this process, so tokens and JWKS change on ` +
        `every restart. Pin one with "deno run jsr:@udibo/oauth2/cli oidc ` +
        `keygen".`,
    );
  }

  await idp.finished;
}
