/**
 * Client authentication shared by the authorization server's endpoints and by
 * the grants, so every endpoint answers an unauthenticated or wrongly
 * authenticated request the same way (RFC 6749 Section 2.3).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
 * @module
 */

import type { ClientCredentials, ClientInterface } from "../models/client.ts";
import { InvalidClientError, InvalidRequestError } from "../errors.ts";
import { parseBasicAuth } from "../utils/basic-auth.ts";
import type { ClientServiceInterface } from "./services/client.ts";

const BASIC_SCHEME = /^ *basic(?: |$)/i;

/**
 * Reads the credentials a request presents by the one client-authentication
 * method it uses: HTTP Basic (RFC 6749 Section 2.3.1), or
 * `client_id`/`client_secret` in `body`, the form body the endpoint already
 * parsed. A `client_id` alone identifies a public client. An `Authorization`
 * header with a scheme other than Basic is not client authentication and is
 * ignored.
 *
 * @throws {InvalidRequestError} If the request uses more than one method —
 *   Basic plus a body `client_secret` or a `client_assertion`, or a body
 *   `client_secret` plus a `client_assertion` — or sends Basic credentials
 *   with a body `client_id` naming a different client.
 * @throws {InvalidClientError} If the request presents no usable credentials,
 *   or its Basic header is malformed.
 */
export function extractClientCredentials(
  request: Request,
  body: FormData,
): ClientCredentials {
  const authorization = request.headers.get("authorization");
  const usesBasic = !!authorization && BASIC_SCHEME.test(authorization);
  const clientId = body.get("client_id");
  const clientSecret = body.get("client_secret");
  const methods = [
    usesBasic,
    clientSecret !== null,
    body.has("client_assertion") || body.has("client_assertion_type"),
  ].filter(Boolean).length;
  if (methods > 1) {
    throw new InvalidRequestError("multiple client authentication methods");
  }

  if (usesBasic) {
    const basicAuth = parseBasicAuth(authorization);
    if (clientId !== null && clientId !== basicAuth.name) {
      throw new InvalidRequestError(
        "client_id does not match the Basic credentials",
      );
    }
    return { clientId: basicAuth.name, clientSecret: basicAuth.pass };
  }

  if (typeof clientId === "string") {
    const credentials: ClientCredentials = { clientId };
    if (typeof clientSecret === "string") {
      credentials.clientSecret = clientSecret;
    }
    return credentials;
  }

  if (authorization) {
    throw new InvalidClientError("unsupported authorization header");
  }
  throw new InvalidClientError("client authentication required");
}

/**
 * Looks up the client the credentials authenticate. Pair it with
 * {@linkcode extractClientCredentials} unless the caller applies its own
 * credential rules (as the authorization-code grant does for PKCE).
 *
 * @throws {InvalidClientError} If no client matches the credentials.
 */
export async function authenticateClientCredentials<
  Client extends ClientInterface,
  User,
>(
  credentials: ClientCredentials,
  clientService: ClientServiceInterface<Client, User>,
): Promise<Client> {
  const client = await clientService.getAuthenticated(
    credentials.clientId,
    credentials.clientSecret,
  );
  if (!client) throw new InvalidClientError("client authentication failed");
  return client;
}
