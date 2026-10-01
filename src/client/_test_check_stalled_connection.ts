/**
 * Test-only child script: asks a check endpoint the same question several
 * times with `checkPermissions` on the default `fetch`, and prints each
 * outcome as JSON. Run by `runTrustingCertificate` with
 * `<endpoint> <attempts>`.
 *
 * @module
 */

import { TemporarilyUnavailableError } from "../errors.ts";
import { checkPermissions } from "./check.ts";

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
console.log(JSON.stringify(outcomes));
