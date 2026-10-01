/**
 * Test-only TLS helpers, excluded from the published package. Deno negotiates
 * HTTP/2 only over TLS, so a test of how `fetch` pools HTTP/2 connections
 * needs a certificate the client trusts — and the global `fetch` trusts only
 * what the process was started with, which is why the client side runs as a
 * sanitized test in a child process started with `--cert`.
 *
 * @module
 */

/** A PEM certificate and its PKCS #8 private key. */
export interface TestCertificate {
  /** The self-signed certificate, valid for `localhost` and `127.0.0.1`. */
  cert: string;
  /** The certificate's private key. */
  key: string;
}

const OID_ECDSA_WITH_SHA256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_COMMON_NAME = [0x55, 0x04, 0x03];
const OID_SUBJECT_ALT_NAME = [0x55, 0x1d, 0x11];
const OID_BASIC_CONSTRAINTS = [0x55, 0x1d, 0x13];

function der(
  tag: number,
  ...contents: Uint8Array[]
): Uint8Array<ArrayBuffer> {
  const length = contents.reduce((sum, part) => sum + part.byteLength, 0);
  const lengthBytes = length < 0x80
    ? [length]
    : length < 0x100
    ? [0x81, length]
    : [0x82, length >> 8, length & 0xff];
  const out = new Uint8Array(1 + lengthBytes.length + length);
  out.set([tag, ...lengthBytes]);
  let offset = 1 + lengthBytes.length;
  for (const part of contents) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

const sequence = (...parts: Uint8Array[]) => der(0x30, ...parts);
const oid = (bytes: number[]) => der(0x06, new Uint8Array(bytes));

function unsignedInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const trimmed = bytes.subarray(start);
  return der(
    0x02,
    trimmed[0] & 0x80 ? new Uint8Array([0, ...trimmed]) : trimmed,
  );
}

function utcTime(date: Date): Uint8Array {
  const text = date.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";
  return der(0x17, new TextEncoder().encode(text));
}

function name(commonName: string): Uint8Array {
  return sequence(
    der(
      0x31,
      sequence(
        oid(OID_COMMON_NAME),
        der(0x0c, new TextEncoder().encode(commonName)),
      ),
    ),
  );
}

function pem(label: string, bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  const lines = base64.match(/.{1,64}/g)!.join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

/**
 * Generates a throwaway self-signed ECDSA P-256 certificate for `localhost`
 * and `127.0.0.1`, valid from an hour ago until a day from now. A process
 * started with `--cert` naming it trusts a server presenting it.
 */
export async function generateTestCertificate(): Promise<TestCertificate> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const spki = new Uint8Array(
    await crypto.subtle.exportKey("spki", pair.publicKey),
  );
  const serial = crypto.getRandomValues(new Uint8Array(8));
  serial[0] &= 0x7f;
  const now = Date.now();
  const signatureAlgorithm = sequence(oid(OID_ECDSA_WITH_SHA256));
  const subjectAltName = sequence(
    der(0x82, new TextEncoder().encode("localhost")),
    der(0x87, new Uint8Array([127, 0, 0, 1])),
  );
  const tbs = sequence(
    der(0xa0, der(0x02, new Uint8Array([2]))),
    unsignedInteger(serial),
    signatureAlgorithm,
    name("localhost"),
    sequence(
      utcTime(new Date(now - 3_600_000)),
      utcTime(new Date(now + 86_400_000)),
    ),
    name("localhost"),
    spki,
    der(
      0xa3,
      sequence(
        sequence(oid(OID_SUBJECT_ALT_NAME), der(0x04, subjectAltName)),
        sequence(
          oid(OID_BASIC_CONSTRAINTS),
          der(0x01, new Uint8Array([0xff])),
          der(0x04, sequence()),
        ),
      ),
    ),
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      pair.privateKey,
      tbs,
    ),
  );
  const certificate = sequence(
    tbs,
    signatureAlgorithm,
    der(
      0x03,
      new Uint8Array([0]),
      sequence(
        unsignedInteger(signature.subarray(0, 32)),
        unsignedInteger(signature.subarray(32)),
      ),
    ),
  );
  const pkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", pair.privateKey),
  );
  return {
    cert: pem("CERTIFICATE", certificate),
    key: pem("PRIVATE KEY", pkcs8),
  };
}

/** What a {@link serveTls} handler knows about the connection a request came in on. */
export interface TestConnection {
  /** True once {@link TlsTestServer.stall} has been called after it opened. */
  stalled: boolean;
  /** Settles when the server is disposed; a stalled handler awaits it. */
  released: Promise<void>;
}

/** A local HTTPS server that can stop answering on the connections it has. */
export interface TlsTestServer extends AsyncDisposable {
  /** `https://localhost:<port>`. */
  url: string;
  /** How many distinct client connections have sent a request so far. */
  readonly connections: number;
  /**
   * Marks every connection opened so far as stalled — a proxy whose existing
   * connections now route to a backend that never answers, while a new
   * connection reaches a live one.
   */
  stall(): void;
}

/**
 * Serves HTTPS (and so HTTP/2) on `127.0.0.1` at a free port, telling the
 * handler whether the request's connection has been stalled.
 */
export function serveTls(
  certificate: TestCertificate,
  handler: (
    request: Request,
    connection: TestConnection,
  ) => Response | Promise<Response>,
): TlsTestServer {
  const seen = new Set<number>();
  const stalled = new Set<number>();
  const released = Promise.withResolvers<void>();
  const server = Deno.serve(
    {
      hostname: "127.0.0.1",
      port: 0,
      onListen() {},
      cert: certificate.cert,
      key: certificate.key,
    },
    (request, info) => {
      const port = info.remoteAddr.port;
      seen.add(port);
      return handler(request, {
        stalled: stalled.has(port),
        released: released.promise,
      });
    },
  );
  return {
    url: `https://localhost:${server.addr.port}`,
    get connections() {
      return seen.size;
    },
    stall() {
      for (const port of seen) stalled.add(port);
    },
    async [Symbol.asyncDispose]() {
      released.resolve();
      await server.shutdown();
    },
  };
}

/**
 * Serves one fixed raw HTTP/1.1 response over TLS on `127.0.0.1` at a free
 * port, for status lines `Deno.serve` cannot produce, then closes each
 * connection.
 */
export function serveRawTls(
  certificate: TestCertificate,
  response: string,
): AsyncDisposable & { url: string } {
  const listener = Deno.listenTls({
    hostname: "127.0.0.1",
    port: 0,
    cert: certificate.cert,
    key: certificate.key,
    alpnProtocols: ["http/1.1"],
  });
  const answered = new Set<Promise<void>>();
  const accepting = (async () => {
    for await (const conn of listener) {
      const answering = answerRaw(conn, response);
      answered.add(answering);
      answering.finally(() => answered.delete(answering));
    }
  })();
  return {
    url: `https://localhost:${listener.addr.port}`,
    async [Symbol.asyncDispose]() {
      listener.close();
      await accepting;
      await Promise.all(answered);
    },
  };
}

async function answerRaw(conn: Deno.TlsConn, response: string): Promise<void> {
  const received = new Uint8Array(64 * 1024);
  let request = "";
  try {
    while (!request.includes("\r\n\r\n")) {
      const read = await conn.read(received);
      if (read === null) return;
      request += new TextDecoder().decode(received.subarray(0, read));
    }
    const bytes = new TextEncoder().encode(response);
    let written = 0;
    while (written < bytes.byteLength) {
      written += await conn.write(bytes.subarray(written));
    }
  } catch (error) {
    if (
      !(error instanceof Deno.errors.BrokenPipe ||
        error instanceof Deno.errors.ConnectionReset)
    ) {
      throw error;
    }
  } finally {
    conn.close();
  }
}

const RESULT_PREFIX = "CHILD RESULT ";
const CHILD_TIMEOUT_MS = 60_000;

/**
 * Registers the one test a {@link runTrustingCertificate} child script runs:
 * `run`'s result is reported back to the parent, and the child's resource and
 * op sanitizers fail it if `run` leaves anything open.
 */
export function childTest(run: () => Promise<unknown>): void {
  Deno.test("child", async () => {
    console.log(RESULT_PREFIX + JSON.stringify(await run()));
  });
}

/**
 * Runs `script` — which registers its work with {@link childTest} — as a
 * sanitized test in a child Deno process that trusts `certificate`, with
 * network access only, and returns what it reported. The child is killed
 * after a minute.
 *
 * @throws {Error} carrying the child's output when it fails, leaks a
 * resource, or runs out of time.
 */
export async function runTrustingCertificate(
  script: URL,
  certificate: TestCertificate,
  args: string[],
): Promise<unknown> {
  const dir = await Deno.makeTempDir();
  try {
    const certFile = `${dir}/cert.pem`;
    await Deno.writeTextFile(certFile, certificate.cert);
    const { code, stdout, stderr } = await new Deno.Command(Deno.execPath(), {
      args: [
        "test",
        "--no-check",
        "--no-prompt",
        "--allow-net",
        `--cert=${certFile}`,
        script.href,
        "--",
        ...args,
      ],
      cwd: new URL(".", import.meta.url),
      stdout: "piped",
      stderr: "piped",
      signal: AbortSignal.timeout(CHILD_TIMEOUT_MS),
    }).output();
    const decoder = new TextDecoder();
    const output = decoder.decode(stdout);
    const result = output.split("\n").find((line) =>
      line.startsWith(RESULT_PREFIX)
    );
    if (code !== 0 || result === undefined) {
      throw new Error(
        `${script.href} exited ${code}:\n${output}\n${decoder.decode(stderr)}`,
      );
    }
    return JSON.parse(result.slice(RESULT_PREFIX.length));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}
