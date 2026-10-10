/**
 * Environment-driven configuration, parsed once at startup so a bad value
 * fails the boot instead of the first request. Every value has a local-dev
 * default, so the app runs with no `.env` file; `.env.example` lists them all.
 *
 * @module
 */

import { z } from "zod";

const environmentSchema = z
  .object({
    ORIGIN: z
      .url({ protocol: /^https?$/ })
      .default("http://localhost:8000")
      .transform((value) => new URL(value).origin),
    PORT: z.coerce.number().int().min(0).max(65535).default(8000),
    APP_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    OAUTH2_CLIENT_SECRET: z.string().min(1).optional(),
  })
  .refine((env) => env.APP_ENV !== "production" || env.OAUTH2_CLIENT_SECRET, {
    path: ["OAUTH2_CLIENT_SECRET"],
    message:
      "must be set when APP_ENV=production — the development fallback is " +
      "public in the template source",
  });

/** Validated settings for this process. */
export interface Config {
  /** Public origin the app is served from; issuer and redirect URIs derive from it. */
  origin: string;
  /** Port the production server listens on. */
  port: number;
  /** True when `APP_ENV=production`: no demo account is seeded. */
  isProduction: boolean;
  /** Cookies are marked `Secure` whenever the app is served over HTTPS. */
  secureCookies: boolean;
  /** Secret for the app's confidential OAuth2 client. */
  clientSecret: string;
}

/**
 * Parses and validates `env`.
 *
 * @throws {Error} Listing every invalid variable when validation fails.
 */
export function parseConfig(env: NodeJS.ProcessEnv): Config {
  const parsed = environmentSchema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map(
      (issue) => `${issue.path.join(".") || "environment"}: ${issue.message}`,
    );
    throw new Error(`Invalid configuration:\n- ${problems.join("\n- ")}`);
  }
  const { ORIGIN, PORT, APP_ENV, OAUTH2_CLIENT_SECRET } = parsed.data;
  return {
    origin: ORIGIN,
    port: PORT,
    isProduction: APP_ENV === "production",
    secureCookies: ORIGIN.startsWith("https:"),
    clientSecret: OAUTH2_CLIENT_SECRET ?? "dev-only-secret",
  };
}

/** Settings for this process, validated at import time. */
export const config: Config = parseConfig(process.env);
