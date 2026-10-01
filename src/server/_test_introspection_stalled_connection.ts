/**
 * Test-only child script: introspects one token several times with an
 * `IntrospectionTokenReader` on the default `fetch`, and prints each outcome
 * as JSON. Run by `runTrustingCertificate` with `<endpoint> <attempts>`.
 *
 * @module
 */

import { TemporarilyUnavailableError } from "../errors.ts";
import { IntrospectionTokenReader } from "./introspection-token-reader.ts";

const [endpoint, attempts] = Deno.args;

const reader = new IntrospectionTokenReader({
  introspectionEndpoint: endpoint,
  clientId: "resource-server",
  clientSecret: "secret",
  fetchTimeoutMs: 2_000,
  getClient: (data) => ({ id: String(data.client_id) }),
});

const outcomes: string[] = [];
for (let attempt = 0; attempt < Number(attempts); attempt++) {
  outcomes.push(
    await reader.getToken("token-1").then(
      (found) => found ? "active" : "inactive",
      (error) =>
        error instanceof TemporarilyUnavailableError
          ? "unavailable"
          : String(error),
    ),
  );
}
console.log(JSON.stringify(outcomes));
