/**
 * Request-origin guard for the identity-provider surface. The credential POSTs
 * (`/login`, `/signup`) and the IDP sign-out (`/logout`) call this to reject
 * forged cross-site requests — login CSRF and forced logout — the same
 * `Origin`/`Referer` check the BFF applies to its own endpoints.
 *
 * @module
 */

/**
 * True when a state-changing request is same-origin: it carries no
 * cross-origin `Origin`/`Referer`. A present, mismatched header is rejected; an
 * absent one is allowed (a top-level navigation carries no `Origin`, and a
 * cross-site browser request can't suppress both without cooperating).
 */
export function isSameOrigin(request: Request): boolean {
  const target = new URL(request.url).origin;
  for (const header of ["origin", "referer"] as const) {
    const value = request.headers.get(header);
    if (value === null) continue;
    try {
      return new URL(value).origin === target;
    } catch {
      return false;
    }
  }
  return true;
}
