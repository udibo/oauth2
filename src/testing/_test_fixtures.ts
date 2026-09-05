/**
 * Private convenience re-exports for the library's own tests.
 *
 * **Not part of the public `@udibo/oauth2/testing` surface** — this file
 * exists so the library's tests can import the `Memory*Service` family
 * along with shared `TestUser` / `TestClient` type aliases from a single
 * path. Public consumers should import the services from
 * `@udibo/oauth2/testing` and declare their own user / client types.
 *
 * @module
 */

import type { ClientInterface } from "../models/client.ts";
import { encodeBasicAuth } from "../utils/basic-auth.ts";

/** Minimal user fixture shape used in the library's own tests. */
export interface TestUser {
  id: string;
  username: string;
}

/**
 * Client fixture shape used in the library's own tests. The
 * `confidential` field is structural-only — `MemoryClientService` infers
 * confidentiality from whether `add()` was called with a secret, not from
 * a flag. It's preserved here so existing fixture literals keep type-checking.
 */
export interface TestClient extends ClientInterface {
  name?: string;
  confidential?: boolean;
  accessTokenLifetime?: number;
  refreshTokenLifetime?: number;
  refreshTokenMaxLifetime?: number;
}

/**
 * Runs a grant's token exchange the way the token endpoint does: the request
 * body parsed once, then handed to the grant.
 */
export async function exchangeToken<Client, T>(
  grant: {
    token(request: Request, client: Client, body: FormData): Promise<T>;
  },
  request: Request,
  client: Client,
): Promise<T> {
  return await grant.token(request, client, await request.clone().formData());
}

/** The token endpoint the library's own tests post to. */
export const TOKEN_ENDPOINT = "http://localhost/token";

/**
 * A form-encoded `POST`, the wire shape every OAuth2 endpoint in this package
 * receives. `fields` may be a plain object or a prebuilt `URLSearchParams`;
 * `headers` merges over (and can override) the form content type.
 */
export function formRequest(
  url: string,
  fields: Record<string, string> | URLSearchParams = {},
  headers: Record<string, string> = {},
): Request {
  return new Request(url, formRequestInit(fields, headers));
}

/**
 * The `RequestInit` half of {@link formRequest}, for Hono's
 * `app.request(path, init)` where the path is supplied separately.
 */
export function formRequestInit(
  fields: Record<string, string> | URLSearchParams = {},
  headers: Record<string, string> = {},
): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(fields),
  };
}

/**
 * A form-encoded request to {@link TOKEN_ENDPOINT}. Pair with
 * {@link basicAuthHeader} when the grant under test authenticates the client.
 */
export function tokenRequest(
  fields: Record<string, string> | URLSearchParams = {},
  headers: Record<string, string> = {},
): Request {
  return formRequest(TOKEN_ENDPOINT, fields, headers);
}

/**
 * An `Authorization: Basic` header carrying a confidential client's
 * credentials, ready to spread into {@link formRequest}'s `headers`. Encodes
 * through the shipped `encodeBasicAuth`, so tests track the production
 * encoding rather than a copy of it.
 */
export function basicAuthHeader(
  clientId: string,
  clientSecret: string,
): Record<string, string> {
  return { authorization: encodeBasicAuth(clientId, clientSecret) };
}

export {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryDeviceAuthorizationService,
  MemoryTokenService,
  MemoryUserService,
} from "./services.ts";
