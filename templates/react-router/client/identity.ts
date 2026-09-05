/**
 * Browser-side helper for the `/identity/*` endpoints the login and sign-up
 * forms post to.
 *
 * On success the server responds with a redirect chain (issuer session →
 * authorize → BFF callback → destination) that `fetch` follows same-origin,
 * setting the session cookies along the way — so the helper finishes with a
 * full navigation to wherever the chain landed. On failure it resolves with a
 * human-readable message for the form to display.
 *
 * @module
 */

const MESSAGES: Record<string, string> = {
  invalid_credentials: "Invalid email or password.",
  identifier_taken: "That email is already registered.",
  weak_password: "Password must be at least 8 characters.",
  rate_limited: "Too many attempts. Try again shortly.",
  invalid_request: "Please fill in every field.",
};

/**
 * Posts `body` as JSON to an `/identity/*` endpoint, forwarding `returnTo` so
 * the server can resume an in-flight authorize URL. Navigates on success;
 * returns an error message on failure.
 */
export async function submitIdentityForm(
  path: string,
  body: Record<string, string>,
  returnTo: string | null,
): Promise<string | null> {
  const url = returnTo
    ? `${path}?return_to=${encodeURIComponent(returnTo)}`
    : path;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.ok) {
    globalThis.location.assign(
      response.redirected ? response.url : "/dashboard",
    );
    return null;
  }
  const data = await response.json().catch(() => ({})) as { error?: string };
  return MESSAGES[data.error ?? ""] ?? "Something went wrong. Try again.";
}
