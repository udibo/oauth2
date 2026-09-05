/**
 * Client for a permission check endpoint — the asynchronous escape hatch for
 * what a credential's own claims cannot answer: an organization the
 * credential was not issued in, any resource-level question, and a decision
 * newer than a token that carries its claims by signature.
 *
 * Freshness is a property of the surface, not of the token, and the surfaces
 * differ in *when* the claims computation runs rather than in which one runs.
 * An introspection response (`introspectionClaims`) and a UserInfo response
 * (`userClaims`) are computed per request, so against an issuer whose hooks
 * answer from live state neither has staleness to escape. A signed JWT access
 * token and an `id_token` embed what that computation returned when they were
 * signed. Wire both hooks: a deployment that implements one leaves the other
 * surface carrying no authorization claims at all.
 *
 * Whatever the surface, this answers only for the scope you name — see the
 * `resource` option, and the failure modes on {@linkcode checkPermissions}
 * before you echo a scope off a signed claim.
 *
 * The endpoint contract this calls is the one Udibo's identity service
 * exposes at `POST /api/check` on the tenant's own host, and any deployment
 * of this package's authorization server can host the same shape: a bearer-
 * authenticated POST answering only for the caller themself, taking
 * `{ permissions, resource? }` and returning each asked permission mapped to
 * whether the caller holds it in the named scope.
 *
 * @module
 */

import { ServerError, TemporarilyUnavailableError } from "../errors.ts";

/** A resource a permission check is scoped to. */
export interface CheckResource {
  /**
   * The resource kind — `organization`, or any application-defined type the
   * endpoint's authorization model recognizes. An unrecognized type is a 400
   * from the endpoint, never a guess.
   */
  type: string;
  /** The resource's id, in the application's own identifier scheme. */
  id: string;
}

/** Options for {@link checkPermissions}. */
export interface CheckPermissionsOptions {
  /** The check endpoint URL, e.g. `https://<tenant>.example.com/api/check`. */
  endpoint: string;
  /** The caller's own bearer access token — the answer is about its subject. */
  accessToken: string;
  /** Permission(s) to ask about. */
  permissions: string | string[];
  /**
   * The resource to scope the answer to. **The answer covers only the scope
   * named here**, so it is interchangeable with a `permissions` claim only
   * when it names the claim's scope: a claim resolved for an organization
   * covers that organization's grants alongside the tenant's, so pass that
   * organization — `{ type: "organization", id: org_id }` — to ask the same
   * question. Any other type asks about that one instance. Omit it and the
   * answer covers whatever scope the endpoint treats as its default, which
   * need not be the claim's; where that default is narrower, a permission the
   * subject holds through an organization comes back `false`.
   */
  resource?: CheckResource;
  /**
   * `fetch` implementation used to call the endpoint. Defaults to the global
   * `fetch`; inject to add timeouts or stub the network in tests.
   */
  fetch?: typeof fetch;
}

/** The check endpoint's answer. */
export interface CheckPermissionsResult {
  /** The subject the answer is about — always the caller themself. */
  subject: string;
  /** The resource the answer was scoped to, `null` for the default scope. */
  resource: CheckResource | null;
  /** Each asked permission mapped to whether the caller holds it. */
  results: Record<string, boolean>;
}

/**
 * Ask a check endpoint whether the caller holds the named permissions.
 *
 * Prefer the token's own claims (`Authorization.can`) for the common case —
 * they answer with no network hop, and on a per-request surface, against an
 * issuer whose hooks answer from live state, they are not a stale answer.
 * Reach for this when the question names a scope the credential was not
 * issued in or one of your own resources, or when the reader validates signed
 * claims locally and the decision must reflect state newer than the
 * signature.
 *
 * Failure modes mirror the introspection reader's: an unreachable endpoint
 * or a 5xx throws {@linkcode TemporarilyUnavailableError} (the service is
 * down — the caller's token is not necessarily bad), and any other non-OK
 * response throws {@linkcode ServerError}. That second case is usually
 * misconfiguration, but not always — a `resource` naming an organization the
 * tenant no longer resolves is a 404 and lands there too. Echoing an `org_id`
 * off a signed claim is how you meet it, because the organization can be
 * deleted after the signature, so catch it on that path rather than reading a
 * throw as a bug in your own setup.
 *
 * @example
 * ```ts
 * import { checkPermissions } from "@udibo/oauth2/client";
 *
 * declare const accessToken: string;
 * declare const otherOrgId: string;
 *
 * const { results } = await checkPermissions({
 *   endpoint: "https://tenant.example.com/api/check",
 *   accessToken,
 *   permissions: "posts:write",
 *   resource: { type: "organization", id: otherOrgId },
 * });
 * if (results["posts:write"]) {
 *   // allowed in that organization
 * }
 * ```
 */
export async function checkPermissions(
  options: CheckPermissionsOptions,
): Promise<CheckPermissionsResult> {
  const fetchImpl = options.fetch ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(options.endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${options.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        permissions: options.permissions,
        ...(options.resource ? { resource: options.resource } : {}),
      }),
    });
  } catch (cause) {
    throw new TemporarilyUnavailableError("check endpoint unreachable", {
      cause,
    });
  }
  if (response.status >= 500) {
    throw new TemporarilyUnavailableError(
      `check endpoint answered ${response.status}`,
    );
  }
  if (!response.ok) {
    throw new ServerError(`check request refused: ${response.status}`);
  }
  return await response.json() as CheckPermissionsResult;
}
