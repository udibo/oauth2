import { readdirSync, readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hangUntilAborted, stubDenoRuntime } from "../_test_deno-runtime.ts";
import { defaultFetch, packageDeadlineSignal } from "./_default-fetch.ts";

let originCount = 0;
let origin = "";

function hangOnSignalElseOk(
  _input: RequestInfo | URL,
  init: RequestInit | undefined,
): Promise<Response> {
  return init?.signal
    ? hangUntilAborted(init.signal)
    : Promise.resolve(new Response("ok"));
}

async function failWith(pending: Promise<unknown>): Promise<string> {
  return await pending.then(
    () => "resolved",
    (error: unknown) => (error as Error).name,
  );
}

async function missPackageDeadline(url: string): Promise<string> {
  const deadline = new AbortController();
  const pending = failWith(
    defaultFetch(url, { signal: packageDeadlineSignal(deadline.signal) }),
  );
  deadline.abort(new DOMException("deadline", "TimeoutError"));
  return await pending;
}

beforeEach(() => {
  origin = `https://issuer-${originCount++}.example.com`;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("defaultFetch", () => {
  it("is the global fetch, called with the caller's arguments, when the runtime has no Deno HTTP client", async () => {
    const response = new Response("ok");
    const fetched = vi.fn(() => Promise.resolve(response));
    vi.stubGlobal("fetch", fetched);
    const init = { signal: AbortSignal.abort() };

    expect(await defaultFetch(`${origin}/answer`, init)).toBe(response);
    expect(fetched).toHaveBeenCalledExactlyOnceWith(`${origin}/answer`, init);
  });

  it("sends every request after a missed package deadline on a new connection", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);

    await defaultFetch(`${origin}/answer`);
    expect(await missPackageDeadline(`${origin}/hang`)).toBe("TimeoutError");
    await defaultFetch(`${origin}/answer`);
    await defaultFetch(`${origin}/answer`);

    expect(
      runtime.requests.map(
        ({ init }) => (init as { client?: unknown } | undefined)?.client,
      ),
    ).toStrictEqual([
      undefined,
      undefined,
      runtime.clients[0],
      runtime.clients[1],
    ]);
    expect(runtime.clients).toHaveLength(2);
    expect(runtime.clients.map((client) => client.closed)).toStrictEqual([
      true,
      true,
    ]);
  });

  it("sends the request after a body that stalled past its package deadline on a new connection", async () => {
    const deadline = new AbortController();
    const signal = packageDeadlineSignal(deadline.signal);
    using runtime = stubDenoRuntime((_input, init) =>
      Promise.resolve(
        init?.signal === signal
          ? new Response(
              new ReadableStream<Uint8Array>({
                start(stream) {
                  signal.addEventListener("abort", () =>
                    stream.error(signal.reason),
                  );
                },
              }),
            )
          : new Response("ok"),
      ),
    );

    const response = await defaultFetch(`${origin}/body`, { signal });
    const reading = failWith(response.text());
    deadline.abort(new DOMException("deadline", "TimeoutError"));
    expect(await reading).toBe("TimeoutError");
    await defaultFetch(`${origin}/answer`);

    expect(runtime.clients).toHaveLength(1);
    expect(runtime.requests.at(-1)?.init).toHaveProperty(
      "client",
      runtime.clients[0],
    );
  });

  it("keeps the pooled connection after a plain abort", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);
    const aborting = new AbortController();
    const deadline = new AbortController();

    const pending = failWith(
      defaultFetch(`${origin}/hang`, {
        signal: packageDeadlineSignal(deadline.signal, aborting.signal),
      }),
    );
    aborting.abort();
    expect(await pending).toBe("AbortError");
    await defaultFetch(`${origin}/answer`);

    expect(runtime.clients).toHaveLength(0);
  });

  it("keeps the pooled connection when the caller aborted before the deadline passed", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);
    const aborting = new AbortController();
    const deadline = new AbortController();

    const pending = failWith(
      defaultFetch(`${origin}/hang`, {
        signal: packageDeadlineSignal(deadline.signal, aborting.signal),
      }),
    );
    aborting.abort();
    deadline.abort(new DOMException("deadline", "TimeoutError"));
    expect(await pending).toBe("AbortError");
    await defaultFetch(`${origin}/answer`);

    expect(runtime.clients).toHaveLength(0);
  });

  it("keeps the pooled connection after the caller's own timeout", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);
    const callerTimeout = new AbortController();
    const withoutDeadline = failWith(
      defaultFetch(`${origin}/hang`, { signal: callerTimeout.signal }),
    );
    callerTimeout.abort(new DOMException("caller", "TimeoutError"));
    expect(await withoutDeadline).toBe("TimeoutError");

    const otherCaller = new AbortController();
    const deadline = new AbortController();
    const withDeadline = failWith(
      defaultFetch(`${origin}/hang`, {
        signal: packageDeadlineSignal(deadline.signal, otherCaller.signal),
      }),
    );
    otherCaller.abort(new DOMException("caller", "TimeoutError"));
    expect(await withDeadline).toBe("TimeoutError");
    await defaultFetch(`${origin}/answer`);

    expect(runtime.clients).toHaveLength(0);
  });

  it("leaves a plain-http origin on the shared pool after a missed deadline", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);
    const plain = origin.replace("https:", "http:");

    expect(await missPackageDeadline(`${plain}/hang`)).toBe("TimeoutError");
    await defaultFetch(`${plain}/answer`);

    expect(runtime.clients).toHaveLength(0);
  });

  it("leaves other origins on the shared pool after one origin missed a deadline", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk);

    expect(await missPackageDeadline(`${origin}/hang`)).toBe("TimeoutError");
    await defaultFetch(`${origin.replace("issuer", "other")}/answer`);

    expect(runtime.clients).toHaveLength(0);
  });

  it("falls back to the shared pool when the runtime cannot open a client", async () => {
    using runtime = stubDenoRuntime(hangOnSignalElseOk, {
      createHttpClient: () => {
        throw new Error("unsupported");
      },
    });

    expect(await missPackageDeadline(`${origin}/hang`)).toBe("TimeoutError");
    const response = await defaultFetch(`${origin}/answer`);

    expect(await response.text()).toBe("ok");
    expect(runtime.requests).toHaveLength(2);
    expect(runtime.requests.at(-1)?.init).toBeUndefined();
  });

  it("hands a caller the global fetch's own response, before and after its origin leaves the pool", async () => {
    const responses = [new Response("first"), new Response("second")];
    using runtime = stubDenoRuntime((_input, init) =>
      init?.signal
        ? hangUntilAborted(init.signal)
        : Promise.resolve(responses.shift()!),
    );

    const before = await defaultFetch(`${origin}/redirect`);
    expect(await missPackageDeadline(`${origin}/hang`)).toBe("TimeoutError");
    const after = await defaultFetch(`${origin}/redirect`);

    expect(await before.text()).toBe("first");
    expect(await after.text()).toBe("second");
    expect(runtime.clients).toHaveLength(1);
  });

  it("returns a response without a readable body as the global fetch built it", async () => {
    const noContent = new Response(null, { status: 204 });
    const failure = Response.error();
    const noBody = [noContent, failure];
    using _runtime = stubDenoRuntime(() => Promise.resolve(noBody.shift()!));
    const signal = packageDeadlineSignal(new AbortController().signal);

    expect(await defaultFetch(`${origin}/none`, { signal })).toBe(noContent);
    expect(await defaultFetch(`${origin}/failure`, { signal })).toBe(failure);
  });

  it("is the only way library code falls back to the global fetch", () => {
    expect(librarySourcesMatching(GLOBAL_FETCH_FALLBACK)).toStrictEqual([]);
  });

  it("is told about every deadline library code sets on a request", () => {
    expect(librarySourcesMatching(UNMARKED_SIGNAL)).toStrictEqual([]);
  });
});

const SOURCE_ROOT = new URL("../", import.meta.url);
const GLOBAL_FETCH_FALLBACK =
  /globalThis\.fetch\b|\?\?\s*\(?\s*fetch\b|=>\s*fetch\s*\(/;
const UNMARKED_SIGNAL = /\bsignal:(?!\s*packageDeadlineSignal\()/;
const NOT_LIBRARY_CODE =
  /(\.test\.tsx?|\.e2e\.ts)$|(^|\/)_test_|^testing\/|^react\/testing\.tsx$|^utils\/_default-fetch\.ts$/;

function librarySourcesMatching(pattern: RegExp): string[] {
  return librarySources("").filter((path) => {
    const code = readFileSync(new URL(path, SOURCE_ROOT), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    return pattern.test(code);
  });
}

function librarySources(dir: string): string[] {
  return readdirSync(new URL(dir, SOURCE_ROOT), {
    withFileTypes: true,
  }).flatMap((entry) => {
    const path = `${dir}${entry.name}`;
    if (entry.isDirectory()) return librarySources(`${path}/`);
    return /\.tsx?$/.test(path) && !NOT_LIBRARY_CODE.test(path) ? [path] : [];
  });
}
