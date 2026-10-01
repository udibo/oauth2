/**
 * Test-only child script: asks a check endpoint the same question several
 * times with `checkPermissions` on the default `fetch`, and reports each
 * outcome. Run by `runTrustingCertificate` with `<endpoint> <attempts>`.
 *
 * @module
 */

import { TemporarilyUnavailableError } from "../errors.ts";
import { childTest } from "../utils/_test_tls.ts";
import { checkPermissions } from "./check.ts";

childTest(async () => {
  const [endpoint, attempts] = Deno.args;
  const outcomes: string[] = [];
  for (let attempt = 0; attempt < Number(attempts); attempt++) {
    outcomes.push(
      await checkPermissions({
        endpoint,
        accessToken: "token-1",
        permissions: "posts:write",
      }).then(
        ({ results }) => results["posts:write"] ? "allowed" : "denied",
        (error) =>
          error instanceof TemporarilyUnavailableError
            ? "unavailable"
            : String(error),
      ),
    );
  }
  return outcomes;
});
