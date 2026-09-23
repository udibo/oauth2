/**
 * A Chrome DevTools Protocol client small enough to own: a WebSocket, a
 * request/response map, and the few commands the React browser tests drive.
 * It exists so `deno task test:browser` needs no npm dependency and no install
 * step beyond a Chromium binary already on the machine.
 *
 * Call {@link chromiumPath} before the suite so a machine without a browser
 * skips it, then {@link launchBrowser} from `beforeAll` and dispose it in
 * `afterAll`. Every wait is wall-clock bounded, so a wedged browser fails the
 * step instead of hanging the job.
 *
 * @module
 */

import { delay } from "@std/async/delay";

const COMMAND_TIMEOUT_MS = 20_000;
const LAUNCH_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 25;
const PROFILE_REMOVE_ATTEMPTS = 10;
const PROFILE_REMOVE_INTERVAL_MS = 100;

interface PendingCommand {
  resolve: (value: Record<string, unknown>) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

class CdpSocket {
  #socket: WebSocket;
  #pending = new Map<number, PendingCommand>();
  #nextId = 1;
  #closed = false;

  constructor(socket: WebSocket) {
    this.#socket = socket;
    socket.onmessage = (event) => this.#receive(String(event.data));
    socket.onclose = () => this.#rejectAll(new Error("CDP socket closed"));
  }

  #receive(raw: string): void {
    const message = JSON.parse(raw) as {
      id?: number;
      result?: Record<string, unknown>;
      error?: { message: string };
    };
    if (message.id === undefined) return;
    const pending = this.#pending.get(message.id);
    if (!pending) return;
    this.#pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) pending.reject(new Error(message.error.message));
    else pending.resolve(message.result ?? {});
  }

  #rejectAll(reason: Error): void {
    for (const [id, pending] of this.#pending) {
      clearTimeout(pending.timer);
      pending.reject(reason);
      this.#pending.delete(id);
    }
  }

  send(
    method: string,
    params: Record<string, unknown>,
    sessionId?: string,
  ): Promise<Record<string, unknown>> {
    if (this.#closed) {
      return Promise.reject(new Error(`${method} after the browser closed`));
    }
    const id = this.#nextId++;
    const { promise, resolve, reject } = Promise.withResolvers<
      Record<string, unknown>
    >();
    const timer = setTimeout(() => {
      this.#pending.delete(id);
      reject(new Error(`${method} timed out after ${COMMAND_TIMEOUT_MS}ms`));
    }, COMMAND_TIMEOUT_MS);
    this.#pending.set(id, { resolve, reject, timer });
    this.#socket.send(JSON.stringify({ id, method, params, sessionId }));
    return promise;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#rejectAll(new Error("CDP socket closing"));
    if (this.#socket.readyState === WebSocket.CLOSED) return;
    const { promise, resolve } = Promise.withResolvers<void>();
    this.#socket.onclose = () => resolve();
    this.#socket.onerror = () => resolve();
    this.#socket.close();
    await promise;
  }
}

/**
 * One browser tab. Input goes through `Input.dispatch*`, so the browser — not
 * page script — decides what a key or click activates.
 */
export class Page {
  #socket: CdpSocket;
  #sessionId: string;

  constructor(socket: CdpSocket, sessionId: string) {
    this.#socket = socket;
    this.#sessionId = sessionId;
  }

  #send(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    return this.#socket.send(method, params, this.#sessionId);
  }

  /** Navigate the tab and wait until `ready` evaluates truthy in the new document. */
  async navigate(url: string, ready: string): Promise<void> {
    await this.#send("Page.navigate", { url });
    await this.waitFor(ready);
  }

  /**
   * Evaluate `expression` in the page and return its value.
   *
   * @throws Error when the expression throws, carrying the page's own message.
   */
  async evaluate<T>(expression: string): Promise<T> {
    const { result, exceptionDetails } = await this.#send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    }) as {
      result: { value?: T };
      exceptionDetails?: { text: string; exception?: { description?: string } };
    };
    if (exceptionDetails) {
      throw new Error(
        exceptionDetails.exception?.description ?? exceptionDetails.text,
      );
    }
    return result.value as T;
  }

  /**
   * Poll until `expression` evaluates truthy.
   *
   * @throws Error naming the expression when it stays falsy past the timeout.
   */
  async waitFor(
    expression: string,
    timeoutMs = COMMAND_TIMEOUT_MS,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!await this.evaluate<boolean>(`Boolean(${expression})`)) {
      if (Date.now() >= deadline) {
        throw new Error(
          `timed out after ${timeoutMs}ms waiting for ${expression}`,
        );
      }
      await delay(POLL_INTERVAL_MS);
    }
  }

  async #nodeId(selector: string): Promise<number> {
    const { root } = await this.#send("DOM.getDocument", { depth: 0 }) as {
      root: { nodeId: number };
    };
    const { nodeId } = await this.#send("DOM.querySelector", {
      nodeId: root.nodeId,
      selector,
    }) as { nodeId: number };
    if (!nodeId) throw new Error(`no element matched ${selector}`);
    return nodeId;
  }

  /** Move keyboard focus to the element, as a Tab would. */
  async focus(selector: string): Promise<void> {
    await this.#send("DOM.focus", { nodeId: await this.#nodeId(selector) });
  }

  /** Press and release `key` on whatever holds focus. */
  async press(key: "Enter" | " "): Promise<void> {
    const named = key === "Enter"
      ? { key, code: "Enter", windowsVirtualKeyCode: 13, text: "\r" }
      : { key, code: "Space", windowsVirtualKeyCode: 32, text: " " };
    await this.#send("Input.dispatchKeyEvent", { type: "keyDown", ...named });
    await this.#send("Input.dispatchKeyEvent", { type: "keyUp", ...named });
  }

  /** Click the element with a real mouse event at its centre. */
  async click(selector: string): Promise<void> {
    const nodeId = await this.#nodeId(selector);
    await this.#send("DOM.scrollIntoViewIfNeeded", { nodeId });
    const { model } = await this.#send("DOM.getBoxModel", { nodeId }) as {
      model: { content: number[] };
    };
    const [x1, y1, , , x3, y3] = model.content;
    const x = (x1 + x3) / 2;
    const y = (y1 + y3) / 2;
    for (const type of ["mousePressed", "mouseReleased"]) {
      await this.#send("Input.dispatchMouseEvent", {
        type,
        x,
        y,
        button: "left",
        clickCount: 1,
      });
    }
  }
}

/** A launched Chromium, disposed by `await using` or an explicit dispose call. */
export interface Browser extends AsyncDisposable {
  /** Open a fresh tab with the `Page`, `DOM` and `Runtime` domains enabled. */
  newPage(): Promise<Page>;
}

async function isFile(path: string): Promise<boolean> {
  try {
    return (await Deno.stat(path)).isFile;
  } catch {
    return false;
  }
}

/**
 * The Chromium binary to drive, or `null` when this machine has none.
 *
 * `CHROMIUM_PATH` wins and is returned unchecked, so a CI job that sets it
 * fails loudly on a missing browser instead of skipping. Otherwise Playwright's
 * cache and the usual system paths are searched. Nothing here installs a
 * browser.
 */
export async function chromiumPath(): Promise<string | null> {
  const explicit = Deno.env.get("CHROMIUM_PATH");
  if (explicit) return explicit;

  const home = Deno.env.get("HOME");
  const candidates: string[] = [];
  if (home) {
    const cache = `${home}/.cache/ms-playwright`;
    try {
      for (const entry of Deno.readDirSync(cache)) {
        if (!entry.name.startsWith("chromium")) continue;
        candidates.push(
          `${cache}/${entry.name}/chrome-linux64/chrome`,
          `${cache}/${entry.name}/chrome-linux/chrome`,
        );
      }
    } catch {
      // No Playwright cache on this machine.
    }
  }
  candidates.push(
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  );
  for (const candidate of candidates) {
    if (await isFile(candidate)) return candidate;
  }
  return null;
}

async function devToolsEndpoint(userDataDir: string): Promise<string> {
  const portFile = `${userDataDir}/DevToolsActivePort`;
  const deadline = Date.now() + LAUNCH_TIMEOUT_MS;
  while (Date.now() < deadline) {
    try {
      const [port, path] = (await Deno.readTextFile(portFile)).split("\n");
      if (port && path) return `ws://127.0.0.1:${port.trim()}${path.trim()}`;
    } catch {
      await delay(POLL_INTERVAL_MS);
    }
  }
  throw new Error(
    `Chromium did not publish ${portFile} within ${LAUNCH_TIMEOUT_MS}ms`,
  );
}

async function removeProfile(userDataDir: string): Promise<void> {
  for (let attempt = 0; attempt < PROFILE_REMOVE_ATTEMPTS; attempt++) {
    try {
      await Deno.remove(userDataDir, { recursive: true });
      return;
    } catch {
      await delay(PROFILE_REMOVE_INTERVAL_MS);
    }
  }
  await Deno.remove(userDataDir, { recursive: true }).catch(() => {});
}

/**
 * Launch headless Chromium with a throwaway profile and connect over CDP. The
 * debugging port is OS-assigned and read back from the profile, so parallel
 * runs never collide.
 *
 * @throws Error when the browser does not publish its port within 30 s; the
 * process and profile are cleaned up first.
 */
export async function launchBrowser(executable: string): Promise<Browser> {
  const userDataDir = await Deno.makeTempDir({ prefix: "oauth2-chrome-" });
  const child = new Deno.Command(executable, {
    args: [
      "--headless=new",
      "--remote-debugging-port=0",
      `--user-data-dir=${userDataDir}`,
      "--no-sandbox",
      "--disable-gpu",
      "--disable-dev-shm-usage",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      "--use-mock-keychain",
    ],
    stdout: "null",
    stderr: "null",
  }).spawn();

  let socket: CdpSocket | undefined;
  const shutdown = async (): Promise<void> => {
    await socket?.close();
    try {
      child.kill("SIGKILL");
    } catch {
      // Already exited.
    }
    await child.status;
    await removeProfile(userDataDir);
  };

  try {
    const endpoint = await devToolsEndpoint(userDataDir);
    const ws = new WebSocket(endpoint);
    const opened = Promise.withResolvers<void>();
    ws.onopen = () => opened.resolve();
    ws.onerror = () =>
      opened.reject(new Error(`could not connect ${endpoint}`));
    await opened.promise;
    socket = new CdpSocket(ws);
  } catch (error) {
    await shutdown();
    throw error;
  }

  const connection = socket;
  return {
    async newPage(): Promise<Page> {
      const { targetId } = await connection.send("Target.createTarget", {
        url: "about:blank",
      }) as { targetId: string };
      const { sessionId } = await connection.send("Target.attachToTarget", {
        targetId,
        flatten: true,
      }) as { sessionId: string };
      for (const domain of ["Page", "DOM", "Runtime"]) {
        await connection.send(`${domain}.enable`, {}, sessionId);
      }
      return new Page(connection, sessionId);
    },
    async [Symbol.asyncDispose](): Promise<void> {
      await shutdown();
    },
  };
}
