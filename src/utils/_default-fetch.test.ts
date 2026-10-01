import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { defaultFetch } from "./_default-fetch.ts";
import {
  generateTestCertificate,
  runTrustingCertificate,
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
    if (pathname === "/answer-then-stall") server.stall();
    return new Response("ok");
  });
  return server;
}

describe("defaultFetch", () => {
  it("sends every request after a timed-out one on a new HTTP/2 connection", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runTrustingCertificate(PLAN, certificate, [
      server.url,
      JSON.stringify([
        { path: "/answer-then-stall" },
        { path: "/answer", timeoutMs: 300 },
        { path: "/answer", timeoutMs: 5_000 },
        { path: "/answer", timeoutMs: 5_000 },
      ]),
    ]);

    assertEquals(outcomes, [
      { status: 200, url: `${server.url}/answer-then-stall`, body: "ok" },
      { error: "TimeoutError" },
      { status: 200, url: `${server.url}/answer`, body: "ok" },
      { status: 200, url: `${server.url}/answer`, body: "ok" },
    ]);
  });

  it("sends the request after a body that stalled past its deadline on a new connection", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runTrustingCertificate(PLAN, certificate, [
      server.url,
      JSON.stringify([
        { path: "/answer-then-stall" },
        { path: "/body", timeoutMs: 300 },
        { path: "/answer", timeoutMs: 5_000 },
      ]),
    ]);

    assertEquals(outcomes, [
      { status: 200, url: `${server.url}/answer-then-stall`, body: "ok" },
      { error: "TimeoutError" },
      { status: 200, url: `${server.url}/answer`, body: "ok" },
    ]);
  });

  it("keeps the pooled connection after an abort that is not a timeout", async () => {
    const certificate = await generateTestCertificate();
    await using server = serveStallable(certificate);

    const outcomes = await runTrustingCertificate(PLAN, certificate, [
      server.url,
      JSON.stringify([
        { path: "/answer" },
        { path: "/hang", abortAfterMs: 200 },
        { path: "/answer" },
      ]),
    ]);

    assertEquals(outcomes, [
      { status: 200, url: `${server.url}/answer`, body: "ok" },
      { error: "AbortError" },
      { status: 200, url: `${server.url}/answer`, body: "ok" },
    ]);
    assertEquals(server.connections, 1);
  });

  it("leaves a plain-http origin on the shared pool after a timeout", async () => {
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
          signal: AbortSignal.timeout(timeoutMs),
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
    const offenders: string[] = [];
    for await (const path of librarySources(SOURCE_ROOT, "")) {
      const code = (await Deno.readTextFile(new URL(path, SOURCE_ROOT)))
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/.*$/gm, "");
      if (GLOBAL_FETCH_FALLBACK.test(code)) offenders.push(path);
    }

    assertEquals(offenders, []);
  });
});

const SOURCE_ROOT = new URL("../", import.meta.url);
const GLOBAL_FETCH_FALLBACK =
  /globalThis\.fetch\b|\?\?\s*\(?\s*fetch\b|=>\s*fetch\s*\(/;
const NOT_LIBRARY_CODE =
  /(\.test\.tsx?|\.e2e\.ts)$|(^|\/)_test_|^testing\/|^react\/testing\.tsx$|^utils\/_default-fetch\.ts$/;

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
