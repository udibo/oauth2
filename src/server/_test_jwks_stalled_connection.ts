/**
 * Test-only child script: validates one token several times with a
 * `JwksTokenReader` on the default `fetch`, and reports each outcome. Run by
 * `runTrustingCertificate` with `<issuer> <token> <attempts>`.
 *
 * @module
 */

import { TemporarilyUnavailableError } from "../errors.ts";
import { childTest } from "../utils/_test_tls.ts";
import { JwksTokenReader } from "./jwks-token-reader.ts";

childTest(async () => {
  const [issuer, token, attempts] = Deno.args;
  const reader = new JwksTokenReader({
    issuer,
    audience: "https://api.example.com",
    fetchTimeoutMs: 2_000,
    minFetchIntervalMs: 0,
    getClient: (claims) => ({ id: String(claims.client_id) }),
  });
  const outcomes: string[] = [];
  for (let attempt = 0; attempt < Number(attempts); attempt++) {
    outcomes.push(
      await reader.getToken(token).then(
        (found) => found ? "valid" : "invalid",
        (error) =>
          error instanceof TemporarilyUnavailableError
            ? "unavailable"
            : String(error),
      ),
    );
  }
  return outcomes;
});
