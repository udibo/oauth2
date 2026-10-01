/**
 * Test-only child script: sends a plan of requests in order with the
 * package's default `fetch`, and prints what each one came back with as JSON.
 * Run by `runTrustingCertificate` with `<base url> <plan JSON>`, where each
 * step names a `path` and optionally a `timeoutMs` deadline or an
 * `abortAfterMs` plain abort.
 *
 * @module
 */

import { defaultFetch } from "./_default-fetch.ts";

interface Step {
  path: string;
  timeoutMs?: number;
  abortAfterMs?: number;
}

type Outcome =
  | { status: number; url: string; body: string }
  | { error: string };

const [base, plan] = Deno.args;

const outcomes: Outcome[] = [];
for (const step of JSON.parse(plan) as Step[]) {
  const controller = new AbortController();
  const abortTimer = step.abortAfterMs === undefined
    ? undefined
    : setTimeout(() => controller.abort(), step.abortAfterMs);
  const signal = step.timeoutMs === undefined
    ? controller.signal
    : AbortSignal.any([controller.signal, AbortSignal.timeout(step.timeoutMs)]);
  try {
    const response = await defaultFetch(`${base}${step.path}`, { signal });
    outcomes.push({
      status: response.status,
      url: response.url,
      body: await response.text(),
    });
  } catch (error) {
    outcomes.push({ error: (error as Error).name });
  } finally {
    clearTimeout(abortTimer);
  }
}
console.log(JSON.stringify(outcomes));
