/**
 * Runtime configuration for the api-service example, read once from
 * `process.env` and validated up front so a typo fails at startup rather than
 * on the first token introspection.
 *
 * Every variable has a default that pairs this service with the
 * `app-with-own-auth` example running locally, so `pnpm start` works without
 * any setup. Set them in the environment (or with `node --env-file=.env`) for
 * a real deployment.
 *
 * @module
 */

/** Validated settings for the api-service example. */
export interface Config {
  /** Port the HTTP server listens on. `0` picks a free port. */
  port: number;
  /** Public origin of this service; the redirect URI is derived from it. */
  publicUrl: string;
  /** Origin of the external authorization server (identity provider). */
  authServerUrl: string;
  /** Client this service authenticates as when calling introspection. */
  clientId: string;
  /** Secret paired with {@linkcode Config.clientId}. */
  clientSecret: string;
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
  const listenPort = port(env, 8002, problems);
  const config: Config = {
    port: listenPort,
    publicUrl: origin(
      env,
      "PUBLIC_URL",
      `http://localhost:${listenPort}`,
      problems,
    ),
    authServerUrl: origin(
      env,
      "AUTH_SERVER_URL",
      "http://localhost:8001",
      problems,
    ),
    clientId: text(env, "CLIENT_ID", "spa"),
    clientSecret: text(env, "CLIENT_SECRET", "spa-secret"),
  };
  if (problems.length > 0) throw new ConfigError(problems);
  return config;
}

/** Settings for this process, validated at import time. */
export const config: Config = loadConfig();
