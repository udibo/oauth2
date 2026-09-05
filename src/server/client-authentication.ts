/**
 * Client authentication shared by the authorization server's endpoints and by
 * the grants, so every endpoint answers an unauthenticated or wrongly
 * authenticated request the same way (RFC 6749 Section 2.3).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3
 * @module
 */

import type { ClientCredentials, ClientInterface } from "../models/client.ts";
import { InvalidClientError } from "../errors.ts";
import { parseBasicAuth, tryParseBasicAuth } from "../utils/basic-auth.ts";
import type { ClientServiceInterface } from "./services/client.ts";

/**
 * Reads the credentials a request presents: HTTP Basic first (RFC 6749 Section
 * 2.3.1), then `client_id`/`client_secret` in `body`, the form body the
 * endpoint already parsed. An `Authorization` header that is not usable Basic
 * falls through to the body, so a request that also carries body credentials
 * authenticates by the method it did present.
 *
 * @throws {InvalidClientError} If the request presents no usable credentials.
 */
export function extractClientCredentials(
  request: Request,
  body: FormData,
): ClientCredentials {
  const authorization = request.headers.get("authorization");

  const basicAuth = tryParseBasicAuth(authorization);
  if (basicAuth) {
    return { clientId: basicAuth.name, clientSecret: basicAuth.pass };
  }

  const clientId = body.get("client_id");
  if (typeof clientId === "string") {
    const credentials: ClientCredentials = { clientId };
    const clientSecret = body.get("client_secret");
    if (typeof clientSecret === "string") {
      credentials.clientSecret = clientSecret;
    }
    return credentials;
  }

  if (authorization) throw parseBasicAuth(authorization);
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
