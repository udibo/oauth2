/**
 * Not part of the public API. The `fetch` the package sends with when its
 * caller injects none: the global `fetch`, resolved at call time, except that
 * on Deno, once a request to an `https` origin misses a deadline the package
 * set (see {@link packageDeadlineSignal}) before its response has fully
 * arrived, later requests to that origin each use a connection of their own
 * instead of the pooled HTTP/2 connection, which may be stalled.
 *
 * @module
 */

interface HttpClient {
  close(): void;
}

type CreateHttpClient = (options: Record<string, never>) => HttpClient;

const NULL_BODY_STATUSES = new Set([204, 205, 304]);

const abandonedOrigins = new Set<string>();

const packageDeadlines = new WeakMap<AbortSignal, AbortSignal>();

/**
 * The signal to send a request with when the package bounds it by its own
 * `deadline`; it also aborts when the caller's `signal` does. Only a request
 * whose signal came from here can move its origin off the pooled connection,
 * and only when `deadline` is what aborted it.
 */
export function packageDeadlineSignal(
  deadline: AbortSignal,
  signal?: AbortSignal | null,
): AbortSignal {
  const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  packageDeadlines.set(combined, deadline);
  return combined;
}

/** The package's default `fetch`; see the module documentation. */
export const defaultFetch: typeof fetch = async (input, init) => {
  const createHttpClient = denoCreateHttpClient();
  const origin = createHttpClient ? httpsOrigin(input) : undefined;
  if (!createHttpClient || origin === undefined) {
    return await globalThis.fetch(input, init);
  }
  if (abandonedOrigins.has(origin)) {
    return await fetchOnOwnConnection(createHttpClient, input, init);
  }

  const signal = init?.signal;
  const deadline = signal ? packageDeadlines.get(signal) : undefined;
  if (!signal || !deadline) return await globalThis.fetch(input, init);

  const abandonIfDeadlineMissed = () => {
    if (deadline.aborted && signal.reason === deadline.reason) {
      abandonedOrigins.add(origin);
    }
  };
  let response: Response;
  try {
    response = await globalThis.fetch(input, init);
  } catch (error) {
    abandonIfDeadlineMissed();
    throw error;
  }
  return watchBody(response, abandonIfDeadlineMissed);
};

function denoCreateHttpClient(): CreateHttpClient | undefined {
  const deno = (globalThis as { Deno?: { createHttpClient?: unknown } }).Deno;
  const create = deno?.createHttpClient;
  return typeof create === "function"
    ? (options) => create.call(deno, options)
    : undefined;
}

function httpsOrigin(input: RequestInfo | URL): string | undefined {
  try {
    const url = new URL(input instanceof Request ? input.url : input);
    return url.protocol === "https:" ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

async function fetchOnOwnConnection(
  createHttpClient: CreateHttpClient,
  input: RequestInfo | URL,
  init: RequestInit | undefined,
): Promise<Response> {
  let client: HttpClient;
  try {
    client = createHttpClient({});
  } catch {
    return await globalThis.fetch(input, init);
  }
  try {
    return await globalThis.fetch(input, { ...init, client } as RequestInit);
  } finally {
    client.close();
  }
}

function watchBody(response: Response, onError: () => void): Response {
  const { body: source, status } = response;
  if (
    !source ||
    status < 200 ||
    status > 599 ||
    NULL_BODY_STATUSES.has(status)
  ) {
    return response;
  }
  const reader = source.getReader();
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch (error) {
        onError();
        controller.error(error);
        return;
      }
      if (chunk.done) controller.close();
      else controller.enqueue(chunk.value);
    },
    cancel: (reason) => reader.cancel(reason),
  });
  return new Response(body, {
    status,
    statusText: response.statusText,
    headers: response.headers,
  });
}
