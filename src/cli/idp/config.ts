/**
 * Configuration for the development identity provider: the shape of the JSON
 * file `idp dev` reads, the built-in demo defaults, and the validation that
 * turns untrusted JSON into a {@link DevIdpConfig}.
 *
 * @module
 */

/** Grant types the development identity provider will serve. */
export interface DevIdpGrantsConfig {
  /** Authorization code grant with PKCE. */
  authorization_code: boolean;
  /** Client credentials grant (machine-to-machine). */
  client_credentials: boolean;
  /** Refresh token grant. */
  refresh_token: boolean;
  /** Resource owner password credentials grant. */
  password: boolean;
}

/** A user seeded into the development identity provider at startup. */
export interface DevIdpUserConfig {
  /** Subject identifier: the `sub` claim and the id the admin API takes. */
  id: string;
  /** Login name typed into the sign-in form. */
  username: string;
  /** Password the sign-in form accepts. Plaintext, because this is a dev tool. */
  password: string;
  /** Extra claims merged into this user's id_token and UserInfo response. */
  claims: Record<string, unknown>;
}

/** A client registered with the development identity provider at startup. */
export interface DevIdpClientConfig {
  /** The `client_id` the application authenticates with. */
  id: string;
  /** Omit for a public (PKCE-only) client; set for a confidential one. */
  secret?: string;
  /** Redirect URIs, matched exactly — list every one your app sends. */
  redirectUris: string[];
  /** Grant types this client may use. */
  grants: string[];
  /**
   * User the client-credentials grant puts on the token. Omit it — the
   * default — for a machine token with no user, whose subject is the client
   * itself (RFC 9068 §2.2). Set it only to model a dedicated service-account
   * user, never a human owner.
   */
  ownerUserId?: string;
}

/**
 * A fully resolved configuration. Every field the server needs is present:
 * {@link parseDevIdpConfig} fills the defaults so nothing downstream has to.
 */
export interface DevIdpConfig {
  /**
   * Issuer identifier stamped into tokens and discovery. When omitted the
   * issuer follows each request's own origin, so the same process answers
   * correctly on `localhost`, `127.0.0.1`, and a CI service hostname.
   */
  issuer?: string;
  /** Interface to bind. */
  hostname: string;
  /** Port to bind. `0` asks the OS for a free one. */
  port: number;
  /** `"prompt"` shows a consent screen; `"auto"` grants the requested scope. */
  consent: "auto" | "prompt";
  /** Scope vocabulary advertised in discovery. */
  scopesSupported: string[];
  /** Access token lifetime in seconds — shorten it to test expiry handling. */
  accessTokenLifetime: number;
  /** Grant types the server enables. */
  grants: DevIdpGrantsConfig;
  /**
   * ES256 private JWK, as printed by `oidc keygen`. Pins the signing key so
   * tokens and JWKS survive a restart. `OIDC_SIGNING_KEY` overrides it.
   */
  signingKey?: JsonWebKey & { kid?: string };
  /** Users to seed. */
  users: DevIdpUserConfig[];
  /** Clients to register. */
  clients: DevIdpClientConfig[];
}

const DEFAULT_PORT = 9000;
const DEFAULT_HOSTNAME = "127.0.0.1";
const DEFAULT_ACCESS_TOKEN_LIFETIME = 3600;
const DEFAULT_SCOPES = ["openid", "profile", "email", "offline_access"];
const DEFAULT_GRANTS: DevIdpGrantsConfig = {
  authorization_code: true,
  client_credentials: true,
  refresh_token: true,
  password: false,
};
const DEFAULT_REDIRECT_URIS = [
  "http://localhost:3000/callback",
  "http://localhost:5173/callback",
  "http://localhost:8000/callback",
];
const DEFAULT_CLIENT_GRANTS = ["authorization_code", "refresh_token"];

const CONFIG_FIELDS = [
  "issuer",
  "hostname",
  "port",
  "consent",
  "scopesSupported",
  "accessTokenLifetime",
  "grants",
  "signingKey",
  "users",
  "clients",
];
const USER_FIELDS = ["id", "username", "password", "claims"];
const CLIENT_FIELDS = [
  "id",
  "secret",
  "redirectUris",
  "grants",
  "ownerUserId",
];

/**
 * The configuration used when `idp dev` runs without `--config`: one
 * confidential client, one public client, and one user, all on well-known
 * localhost ports.
 */
export function defaultDevIdpConfig(): DevIdpConfig {
  return {
    hostname: DEFAULT_HOSTNAME,
    port: DEFAULT_PORT,
    consent: "auto",
    scopesSupported: [...DEFAULT_SCOPES],
    accessTokenLifetime: DEFAULT_ACCESS_TOKEN_LIFETIME,
    grants: { ...DEFAULT_GRANTS },
    users: [{
      id: "user-alice",
      username: "alice@example.com",
      password: "password",
      claims: {
        name: "Alice Example",
        email: "alice@example.com",
        email_verified: true,
      },
    }],
    clients: [
      {
        id: "dev-client",
        secret: "dev-secret",
        redirectUris: [...DEFAULT_REDIRECT_URIS],
        grants: [
          "authorization_code",
          "refresh_token",
          "client_credentials",
        ],
        ownerUserId: "user-alice",
      },
      {
        id: "dev-public-client",
        redirectUris: [...DEFAULT_REDIRECT_URIS],
        grants: [...DEFAULT_CLIENT_GRANTS],
      },
    ],
  };
}

function fail(path: string, expectation: string): never {
  throw new Error(`${path} ${expectation}`);
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(path, "must be an object");
  }
  return value as Record<string, unknown>;
}

function rejectUnknown(
  value: Record<string, unknown>,
  path: string,
  allowed: string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      fail(
        `${path}.${key}`,
        `is not a known option (expected one of: ${allowed.join(", ")})`,
      );
    }
  }
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(path, "must be a non-empty string");
  }
  return value;
}

function optionalString(value: unknown, path: string): string | undefined {
  return value === undefined ? undefined : string(value, path);
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) fail(path, "must be an array of strings");
  return value.map((entry, index) => string(entry, `${path}[${index}]`));
}

function integer(value: unknown, path: string, min: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min) {
    fail(path, `must be an integer >= ${min}`);
  }
  return value;
}

function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") fail(path, "must be true or false");
  return value;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path, "must be an array");
  return value;
}

function parseGrants(value: unknown, path: string): DevIdpGrantsConfig {
  const source = record(value, path);
  rejectUnknown(source, path, Object.keys(DEFAULT_GRANTS));
  const grants = { ...DEFAULT_GRANTS };
  for (
    const key of Object.keys(DEFAULT_GRANTS) as (keyof DevIdpGrantsConfig)[]
  ) {
    if (source[key] !== undefined) {
      grants[key] = boolean(source[key], `${path}.${key}`);
    }
  }
  return grants;
}

function parseUser(value: unknown, path: string): DevIdpUserConfig {
  const source = record(value, path);
  rejectUnknown(source, path, USER_FIELDS);
  const username = string(source.username, `${path}.username`);
  return {
    id: optionalString(source.id, `${path}.id`) ?? username,
    username,
    password: string(source.password, `${path}.password`),
    claims: source.claims === undefined
      ? {}
      : record(source.claims, `${path}.claims`),
  };
}

function parseClient(value: unknown, path: string): DevIdpClientConfig {
  const source = record(value, path);
  rejectUnknown(source, path, CLIENT_FIELDS);
  const grants = source.grants === undefined
    ? [...DEFAULT_CLIENT_GRANTS]
    : stringArray(source.grants, `${path}.grants`);
  const redirectUris = source.redirectUris === undefined
    ? []
    : stringArray(source.redirectUris, `${path}.redirectUris`);
  if (grants.includes("authorization_code") && redirectUris.length === 0) {
    fail(
      `${path}.redirectUris`,
      "must list at least one URI for a client using the authorization_code grant",
    );
  }
  return {
    id: string(source.id, `${path}.id`),
    secret: optionalString(source.secret, `${path}.secret`),
    redirectUris,
    grants,
    ownerUserId: optionalString(source.ownerUserId, `${path}.ownerUserId`),
  };
}

function parseConsent(value: unknown, path: string): "auto" | "prompt" {
  const consent = string(value, path);
  if (consent !== "auto" && consent !== "prompt") {
    fail(path, 'must be "auto" or "prompt"');
  }
  return consent;
}

function parseSigningKey(
  value: unknown,
  path: string,
): JsonWebKey & { kid?: string } {
  const jwk = record(value, path);
  string(jwk.kty, `${path}.kty`);
  string(jwk.d, `${path}.d`);
  return jwk as JsonWebKey & { kid?: string };
}

/**
 * Validates parsed JSON and fills in defaults, so the caller gets a config
 * with no optional plumbing left to resolve.
 *
 * Unknown fields are rejected rather than ignored — a typo in a dev config is
 * otherwise a silent no-op that costs an hour.
 *
 * @throws {Error} When a field is missing, mistyped, or unrecognized. The
 * message names the offending path (e.g. `users[0].password`).
 */
export function parseDevIdpConfig(value: unknown): DevIdpConfig {
  const source = record(value, "config");
  rejectUnknown(source, "config", CONFIG_FIELDS);
  const defaults = defaultDevIdpConfig();

  const users = source.users === undefined
    ? defaults.users
    : array(source.users, "config.users").map((entry, index) =>
      parseUser(entry, `users[${index}]`)
    );
  const clients = source.clients === undefined
    ? defaults.clients
    : array(source.clients, "config.clients").map((entry, index) =>
      parseClient(entry, `clients[${index}]`)
    );

  const seenUserIds = new Set<string>();
  for (const user of users) {
    if (seenUserIds.has(user.id)) {
      fail(`users`, `contains more than one user with id "${user.id}"`);
    }
    seenUserIds.add(user.id);
  }
  const seenClientIds = new Set<string>();
  for (const client of clients) {
    if (seenClientIds.has(client.id)) {
      fail(`clients`, `contains more than one client with id "${client.id}"`);
    }
    seenClientIds.add(client.id);
  }

  return {
    issuer: optionalString(source.issuer, "config.issuer"),
    hostname: optionalString(source.hostname, "config.hostname") ??
      defaults.hostname,
    port: source.port === undefined
      ? defaults.port
      : integer(source.port, "config.port", 0),
    consent: source.consent === undefined
      ? defaults.consent
      : parseConsent(source.consent, "config.consent"),
    scopesSupported: source.scopesSupported === undefined
      ? defaults.scopesSupported
      : stringArray(source.scopesSupported, "config.scopesSupported"),
    accessTokenLifetime: source.accessTokenLifetime === undefined
      ? defaults.accessTokenLifetime
      : integer(source.accessTokenLifetime, "config.accessTokenLifetime", 1),
    grants: source.grants === undefined
      ? defaults.grants
      : parseGrants(source.grants, "config.grants"),
    signingKey: source.signingKey === undefined
      ? undefined
      : parseSigningKey(source.signingKey, "config.signingKey"),
    users,
    clients,
  };
}

/**
 * Reads and validates a config file.
 *
 * @throws {Error} When the file is unreadable, is not valid JSON, or fails
 * {@link parseDevIdpConfig}. Every message names the file.
 */
export async function loadDevIdpConfig(path: string): Promise<DevIdpConfig> {
  let text: string;
  try {
    text = await Deno.readTextFile(path);
  } catch (error) {
    throw new Error(
      `cannot read config ${path}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `${path} is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  try {
    return parseDevIdpConfig(parsed);
  } catch (error) {
    throw new Error(
      `${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
