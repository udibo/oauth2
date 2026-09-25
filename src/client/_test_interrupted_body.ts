const encoder = new TextEncoder();

/** A local endpoint whose response never finishes arriving. */
export interface InterruptedBodyServer extends AsyncDisposable {
  url: string;
}

/**
 * Accepts every request and never sends response headers: each request hangs
 * until the client gives up or the server is disposed.
 */
export function serveNoHeaders(): InterruptedBodyServer {
  const pending = new Set<() => void>();
  const server = Deno.serve(
    { port: 0, hostname: "127.0.0.1", onListen: () => {} },
    (request) =>
      new Promise<Response>((resolve) => {
        const answer = () => {
          pending.delete(answer);
          resolve(new Response(null, { status: 503 }));
        };
        pending.add(answer);
        request.signal.addEventListener("abort", answer, { once: true });
      }),
  );
  return {
    url: `http://127.0.0.1:${server.addr.port}/`,
    async [Symbol.asyncDispose]() {
      for (const answer of pending) answer();
      await server.shutdown();
    },
  };
}

/**
 * Serves a `200` JSON response that sends its headers and the first bytes of
 * the body, then stalls until the server is disposed.
 */
export function serveStalledBody(partial: string): InterruptedBodyServer {
  const stalled = new Set<ReadableStreamDefaultController<Uint8Array>>();
  const server = Deno.serve(
    { port: 0, hostname: "127.0.0.1", onListen: () => {} },
    () => {
      let open: ReadableStreamDefaultController<Uint8Array>;
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            open = controller;
            stalled.add(controller);
            controller.enqueue(encoder.encode(partial));
          },
          cancel() {
            stalled.delete(open);
          },
        }),
        { headers: { "content-type": "application/json" } },
      );
    },
  );
  return {
    url: `http://127.0.0.1:${server.addr.port}/`,
    async [Symbol.asyncDispose]() {
      for (const controller of stalled) controller.close();
      await server.shutdown();
    },
  };
}

/**
 * Answers every connection with a `200` whose `content-length` promises more
 * body than it sends, then closes the connection.
 */
export function serveDroppedBody(partial: string): InterruptedBodyServer {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const connections = new Set<Promise<void>>();
  const accepting = (async () => {
    for await (const conn of listener) {
      const handled = answerThenDrop(conn, partial);
      connections.add(handled);
      handled.finally(() => connections.delete(handled));
    }
  })();
  return {
    url: `http://127.0.0.1:${listener.addr.port}/`,
    async [Symbol.asyncDispose]() {
      listener.close();
      await accepting;
      await Promise.all(connections);
    },
  };
}

async function answerThenDrop(conn: Deno.Conn, partial: string): Promise<void> {
  try {
    const request = new Uint8Array(64 * 1024);
    await conn.read(request);
    const body = encoder.encode(partial);
    await writeAll(
      conn,
      encoder.encode(
        "HTTP/1.1 200 OK\r\n" +
          "content-type: application/json\r\n" +
          `content-length: ${body.byteLength + 1024}\r\n` +
          "connection: close\r\n\r\n",
      ),
    );
    await writeAll(conn, body);
  } catch (error) {
    if (!isClientHangup(error)) throw error;
  } finally {
    conn.close();
  }
}

async function writeAll(conn: Deno.Conn, bytes: Uint8Array): Promise<void> {
  let written = 0;
  while (written < bytes.byteLength) {
    written += await conn.write(bytes.subarray(written));
  }
}

function isClientHangup(error: unknown): boolean {
  return error instanceof Deno.errors.BrokenPipe ||
    error instanceof Deno.errors.ConnectionReset;
}
