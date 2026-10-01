/**
 * Test-only child script: sends a plan of requests in order with the
 * package's default `fetch`, and reports what each one came back with. Run by
 * `runTrustingCertificate` with `<plan JSON>`, where each step names a `url`
 * and optionally a package `deadlineMs`, a caller's own `callerTimeoutMs`, an
 * `abortAfterMs` plain abort, and `inspect` to report how the response
 * presents to a consumer instead of its body. A step with no package deadline
 * is bounded by a caller timeout of ten seconds.
 *
 * @module
 */

import { defaultFetch, packageDeadlineSignal } from "./_default-fetch.ts";
import { childTest } from "./_test_tls.ts";

interface Step {
  url: string;
  deadlineMs?: number;
  callerTimeoutMs?: number;
  abortAfterMs?: number;
  inspect?: boolean;
}

const CALLER_TIMEOUT_MS = 10_000;

function signalFor(step: Step, controller: AbortController): AbortSignal {
  const caller = AbortSignal.any([
    controller.signal,
    AbortSignal.timeout(step.callerTimeoutMs ?? CALLER_TIMEOUT_MS),
  ]);
  return step.deadlineMs === undefined
    ? caller
    : packageDeadlineSignal(AbortSignal.timeout(step.deadlineMs), caller);
}

async function inspect(response: Response): Promise<Record<string, unknown>> {
  let headersImmutable = false;
  try {
    response.headers.set("x-probe", "1");
  } catch {
    headersImmutable = true;
  }
  const reader = response.body!.getReader({ mode: "byob" });
  let body = "";
  while (true) {
    const { done, value } = await reader.read(new Uint8Array(1024));
    if (done) break;
    body += new TextDecoder().decode(value);
  }
  return {
    status: response.status,
    url: response.url,
    redirected: response.redirected,
    type: response.type,
    headersImmutable,
    body,
  };
}

childTest(async () => {
  const outcomes: Record<string, unknown>[] = [];
  for (const step of JSON.parse(Deno.args[0]) as Step[]) {
    const controller = new AbortController();
    const abortTimer = step.abortAfterMs === undefined
      ? undefined
      : setTimeout(() => controller.abort(), step.abortAfterMs);
    try {
      const response = await defaultFetch(step.url, {
        signal: signalFor(step, controller),
      });
      outcomes.push(
        step.inspect
          ? await inspect(response)
          : { status: response.status, body: await response.text() },
      );
    } catch (error) {
      outcomes.push({ error: (error as Error).name });
    } finally {
      clearTimeout(abortTimer);
    }
  }
  return outcomes;
});
