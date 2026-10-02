import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { defaultFetch, packageDeadlineSignal } from "./_default-fetch.ts";
import {
  generateTestCertificate,
  runTrustingCertificate,
  serveRawTls,
  serveTls,
  type TestCertificate,
  type TlsTestServer,
} from "./_test_tls.ts";

const PLAN = new URL("./_test_default_fetch_plan.ts", import.meta.url);

function serveStallable(certificate: TestCertificate): TlsTestServer {
  const server = serveTls(certificate, async (request, connection) => {
    const { pathname } = new URL(request.url);
    if (
      pathname === "/hang" || (pathname === "/answer" && connection.stalled)
    ) {
      await connection.released;
      return new Response(null, { status: 503 });
    }
    if (pathname === "/body" && connection.stalled) {
      let open = true;
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("partial"));
            connection.released.then(() => {
              if (open) controller.close();
            });
          },
          cancel() {
            open = false;
          },
        }),
      );
    }
    if (pathname === "/redirect") {
      return new Response(null, {
        status: 302,
        headers: { location: "/answer" },
      });
    }
    if (pathname === "/answer-then-stall") server.stall();
    return new Response("ok");
  });
  return server;
}

async function runPlan(
  certificate: TestCertificate,
  steps: Record<string, unknown>[],
): Promise<unknown> {
  return await runTrustingCertificate(PLAN, certificate, [
    JSON.stringify(steps),
  ]);
}

const OK = { status: 200, body: "ok" };

describe("defaultFetch", () => {
  it("sends every request after a missed package deadline on a new HTTP/2 connection", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);
    const answer = `${server.url}/answer`;

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/answer-then-stall`, deadlineMs: 5_000 },
      { url: answer, deadlineMs: 300 },
      { url: answer, deadlineMs: 5_000 },
      { url: answer, deadlineMs: 5_000 },
    ]);

    assertEquals(outcomes, [OK, { error: "TimeoutError" }, OK, OK]);
  });

  it("sends the request after a body that stalled past its package deadline on a new connection", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/answer-then-stall`, deadlineMs: 5_000 },
      { url: `${server.url}/body`, deadlineMs: 300 },
      { url: `${server.url}/answer`, deadlineMs: 5_000 },
    ]);

    assertEquals(outcomes, [OK, { error: "TimeoutError" }, OK]);
  });

  it("keeps the pooled connection after a plain abort", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/answer`, deadlineMs: 5_000 },
      { url: `${server.url}/hang`, deadlineMs: 5_000, abortAfterMs: 200 },
      { url: `${server.url}/answer`, deadlineMs: 5_000 },
    ]);

    assertEquals(outcomes, [OK, { error: "AbortError" }, OK]);
    assertEquals(server.connections, 1);
  });

  it("keeps the pooled connection after the caller's own timeout", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/answer` },
      { url: `${server.url}/hang`, callerTimeoutMs: 200 },
      { url: `${server.url}/answer` },
      { url: `${server.url}/hang`, deadlineMs: 5_000, callerTimeoutMs: 200 },
      { url: `${server.url}/answer` },
    ]);

    assertEquals(outcomes, [
      OK,
      { error: "TimeoutError" },
      OK,
      { error: "TimeoutError" },
      OK,
    ]);
    assertEquals(server.connections, 1);
  });

  it("returns a response whose status a Response cannot be built with", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveRawTls(
      certificate,
      "HTTP/1.1 999 Unusual\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
    );

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/`, deadlineMs: 5_000 },
    ]);

    assertEquals(outcomes, [{ status: 999, body: "ok" }]);
  });

  it("hands a caller the global fetch's response, before and after its origin leaves the pool", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);
    const asReceived = {
      status: 200,
      url: `${server.url}/answer`,
      redirected: true,
      type: "basic",
      headersImmutable: true,
      body: "ok",
    };

    const outcomes = await runPlan(certificate, [
      { url: `${server.url}/redirect`, inspect: true },
      { url: `${server.url}/answer-then-stall`, deadlineMs: 5_000 },
      { url: `${server.url}/answer`, deadlineMs: 300 },
      { url: `${server.url}/redirect`, inspect: true },
    ]);

    assertEquals(outcomes, [
      asReceived,
      OK,
      { error: "TimeoutError" },
      asReceived,
    ]);
  });

  it("leaves a plain-http origin on the shared pool after a missed deadline", async () => {
    const connections = new Set<number>();
    const released = Promise.withResolvers<void>();
    await using server = Deno.serve(
      { hostname: "127.0.0.1", port: 0, onListen() {} },
      async (request, info) => {
        connections.add(info.remoteAddr.port);
        if (new URL(request.url).pathname === "/hang") {
          await released.promise;
          return new Response(null, { status: 503 });
        }
        return new Response("ok");
      },
    );
    const base = `http://127.0.0.1:${server.addr.port}`;
    const send = async (path: string, timeoutMs: number) => {
      try {
        const response = await defaultFetch(`${base}${path}`, {
          signal: packageDeadlineSignal(AbortSignal.timeout(timeoutMs)),
        });
        return await response.text();
      } catch (error) {
        return (error as Error).name;
      }
    };

    const outcomes = [
      await send("/answer", 5_000),
      await send("/hang", 200),
      await send("/answer", 5_000),
      await send("/answer", 5_000),
    ];
    released.resolve();

    assertEquals(outcomes, ["ok", "TimeoutError", "ok", "ok"]);
    assertEquals(connections.size, 2);
  });

  it("is the only way library code falls back to the global fetch", async () => {
    assertEquals(await librarySourcesMatching(GLOBAL_FETCH_FALLBACK), []);
  });

  it("is told about every deadline library code sets on a request", async () => {
    assertEquals(await librarySourcesMatching(UNMARKED_SIGNAL), []);
  });
});

const SOURCE_ROOT = new URL("../", import.meta.url);
const GLOBAL_FETCH_FALLBACK =
  /globalThis\.fetch\b|\?\?\s*\(?\s*fetch\b|=>\s*fetch\s*\(/;
const UNMARKED_SIGNAL = /\bsignal:(?!\s*packageDeadlineSignal\()/;
const NOT_LIBRARY_CODE =
  /(\.test\.tsx?|\.e2e\.ts)$|(^|\/)_test_|^testing\/|^react\/testing\.tsx$|^utils\/_default-fetch\.ts$/;

async function librarySourcesMatching(pattern: RegExp): Promise<string[]> {
  const matching: string[] = [];
  for await (const path of librarySources(SOURCE_ROOT, "")) {
    const code = (await Deno.readTextFile(new URL(path, SOURCE_ROOT)))
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    if (pattern.test(code)) matching.push(path);
  }
  return matching;
}

async function* librarySources(
  root: URL,
  dir: string,
): AsyncGenerator<string> {
  for await (const entry of Deno.readDir(new URL(dir, root))) {
    const path = `${dir}${entry.name}`;
    if (entry.isDirectory) yield* librarySources(root, `${path}/`);
    else if (/\.tsx?$/.test(path) && !NOT_LIBRARY_CODE.test(path)) yield path;
  }
}
