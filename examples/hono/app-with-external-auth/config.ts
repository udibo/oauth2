/**
 * Runtime configuration for the app-with-external-auth example, read once from
 * `process.env` and validated up front so a typo fails at startup rather than
 * on the first token introspection.
 *
 * Every variable has a default that pairs this service with the
 * `app-with-own-auth` example (and `api-service` for the proxied route) running
 * locally, so `pnpm start` works without
 * any setup. Set them in the environment (or with `node --env-file=.env`) for
 * a real deployment.
 *
 * @module
 */

/** Validated settings for the app-with-external-auth example. */
export interface Config {
  /** Port the HTTP server listens on. `0` picks a free port. */
  port: number;
  /** Public origin of this app; the OAuth2 redirect URI is derived from it. */
  publicUrl: string;
  /** Origin of the external identity provider. */
  idpBaseUrl: string;
  /** Client this app is registered as at the identity provider. */
  idpClientId: string;
  /** Secret paired with {@linkcode Config.idpClientId}. */
  idpClientSecret: string;
  /** Base URL of the separate API that `/remote-api/*` proxies to. */
  apiServiceUrl: string;
}

/** Thrown by {@linkcode loadConfig} listing every invalid variable at once. */
export class ConfigError extends Error {
  problems: string[];

  constructor(problems: string[]) {
    super(`Invalid configuration:\n- ${problems.join("\n- ")}`);
    this.name = "ConfigError";
    this.problems = problems;
  }
}

function origin(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: string,
  problems: string[],
): string {
  const value = env[name] || fallback;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("not http(s)");
    }
    return url.origin;
  } catch {
    problems.push(`${name} must be an http(s) URL, got "${value}"`);
    return fallback;
  }
}

function url(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: string,
  problems: string[],
): string {
  const value = env[name] || fallback;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("not http(s)");
    }
    return value.replace(/\/+$/, "");
  } catch {
    problems.push(`${name} must be an http(s) URL, got "${value}"`);
    return fallback;
  }
}

function text(env: NodeJS.ProcessEnv, name: string, fallback: string): string {
  return env[name]?.trim() || fallback;
}

function port(
  env: NodeJS.ProcessEnv,
  fallback: number,
  problems: string[],
): number {
  const raw = env.PORT;
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    problems.push(`PORT must be an integer from 0 to 65535, got "${raw}"`);
    return fallback;
  }
  return value;
}

/**
 * Reads and validates the example's settings from `env`.
 *
 * @throws {ConfigError} When any variable is malformed.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];
  const listenPort = port(env, 8003, problems);
  const config: Config = {
    port: listenPort,
    publicUrl: origin(
      env,
      "PUBLIC_URL",
      `http://localhost:${listenPort}`,
      problems,
    ),
    idpBaseUrl: origin(env, "IDP_BASE_URL", "http://localhost:8001", problems),
    idpClientId: text(env, "IDP_CLIENT_ID", "spa"),
    idpClientSecret: text(env, "IDP_CLIENT_SECRET", "spa-secret"),
    apiServiceUrl: url(
      env,
      "API_SERVICE_URL",
      "http://localhost:8002/api",
      problems,
    ),
  };
  if (problems.length > 0) throw new ConfigError(problems);
  return config;
}

/** Settings for this process, validated at import time. */
export const config: Config = loadConfig();
