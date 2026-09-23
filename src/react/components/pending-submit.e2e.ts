/**
 * The drop-in forms' pending submit, driven in headless Chromium.
 *
 * A pending submit button carries `aria-disabled` rather than `disabled`
 * because Chromium moves focus from a focused element to `<body>` the moment it
 * becomes disabled. jsdom has no such focus fixup, so `pending-submit.test.tsx`
 * passes against either attribute; only a real engine shows the difference.
 *
 * Not `*.test.ts`, so `deno task test` does not pick it up — it runs as
 * `deno task test:browser`, which skips when no Chromium is found.
 *
 * @module
 */

import { assertEquals, assertFalse } from "@std/assert";
import { delay } from "@std/async/delay";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import {
  type Browser,
  chromiumPath,
  launchBrowser,
  type Page,
} from "../_test_cdp.ts";

const FORMS = [
  { name: "SignInForm", label: "Sign in", pendingLabel: "Signing in…" },
  {
    name: "SignUpForm",
    label: "Create account",
    pendingLabel: "Creating account…",
  },
  {
    name: "RequestPasswordResetForm",
    label: "Send reset link",
    pendingLabel: "Sending…",
  },
  {
    name: "ResetPasswordForm",
    label: "Reset password",
    pendingLabel: "Resetting…",
  },
  { name: "MfaChallengeForm", label: "Verify", pendingLabel: "Verifying…" },
  { name: "MfaEnrollmentForm", label: "Confirm", pendingLabel: "Confirming…" },
] as const;

const SUBMIT = "[data-oauth2-submit]";
const BUTTON = `document.querySelector(${JSON.stringify(SUBMIT)})`;
const CALLS = "globalThis.pendingSubmit.calls";
const SUBMITS = "globalThis.pendingSubmit.submits";
const FOCUSED = `(() => {
  const active = document.activeElement;
  return active === ${BUTTON} ? "the submit button" : active?.tagName ?? "nothing";
})()`;
const REPEAT_SETTLE_MS = 100;

const chromium = await chromiumPath();
if (chromium === null) {
  console.warn(
    "No Chromium found. Set CHROMIUM_PATH, or install one into " +
      "~/.cache/ms-playwright. The React browser tests are skipped.",
  );
}

async function bundlePage(): Promise<string> {
  const outDir = await Deno.makeTempDir({ prefix: "oauth2-e2e-" });
  try {
    const output = `${outDir}/page.js`;
    const { success, stderr } = await new Deno.Command(Deno.execPath(), {
      args: [
        "bundle",
        "--platform=browser",
        "--quiet",
        "-o",
        output,
        "react/components/_test_pending_submit_page.tsx",
      ],
      cwd: new URL("../../", import.meta.url),
      stdout: "null",
      stderr: "piped",
    }).output();
    if (!success) {
      throw new Error(
        `deno bundle failed:\n${new TextDecoder().decode(stderr)}`,
      );
    }
    return await Deno.readTextFile(output);
  } finally {
    await Deno.remove(outDir, { recursive: true });
  }
}

function servePage(script: string): Deno.HttpServer<Deno.NetAddr> {
  const html = '<!doctype html><html lang="en"><body><div id="root"></div>' +
    '<script type="module" src="/page.js"></script></body></html>';
  return Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen: () => {} },
    (request) => {
      const { pathname } = new URL(request.url);
      if (pathname === "/page.js") {
        return new Response(script, {
          headers: { "content-type": "text/javascript" },
        });
      }
      if (pathname === "/") {
        return new Response(html, {
          headers: { "content-type": "text/html" },
        });
      }
      return new Response("Not found", { status: 404 });
    },
  );
}

describe("a pending submit in a real browser", {
  ignore: chromium === null,
}, () => {
  let server: Deno.HttpServer<Deno.NetAddr>;
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    server = servePage(await bundlePage());
    browser = await launchBrowser(chromium!);
    page = await browser.newPage();
  });

  afterAll(async () => {
    await browser?.[Symbol.asyncDispose]();
    await server?.shutdown();
  });

  for (const form of FORMS) {
    it(`${form.name} keeps focus on its pending button and submits once`, async () => {
      const { port } = server.addr;
      await page.navigate(
        `http://127.0.0.1:${port}/?form=${form.name}`,
        `${BUTTON}?.textContent === ${JSON.stringify(form.label)}`,
      );

      await page.focus(SUBMIT);
      await page.press("Enter");
      await page.waitFor(
        `${BUTTON}.textContent === ${JSON.stringify(form.pendingLabel)}`,
      );

      assertEquals(
        await page.evaluate<string>(FOCUSED),
        "the submit button",
        "a pending submit must keep focus; a natively disabled one hands it to <body>",
      );
      assertEquals(
        await page.evaluate<string | null>(
          `${BUTTON}.getAttribute("aria-disabled")`,
        ),
        "true",
      );
      assertFalse(await page.evaluate<boolean>(`${BUTTON}.disabled`));
      assertEquals(await page.evaluate<number>(CALLS), 1);

      await page.press("Enter");
      await page.press(" ");
      await page.click(SUBMIT);
      await delay(REPEAT_SETTLE_MS);
      assertEquals(
        await page.evaluate<number>(CALLS),
        1,
        "Enter, Space and a click on a pending submit must not submit again",
      );
      assertEquals(
        await page.evaluate<number>(SUBMITS),
        1,
        "the pending button must cancel activation, so its form never posts again",
      );
      assertEquals(await page.evaluate<string>(FOCUSED), "the submit button");

      await page.evaluate("globalThis.pendingSubmit.release()");
      await page.waitFor(
        `${BUTTON}.textContent === ${JSON.stringify(form.label)}`,
      );
      assertFalse(
        await page.evaluate<boolean>(`${BUTTON}.hasAttribute("aria-disabled")`),
      );

      await page.focus(SUBMIT);
      await page.press(" ");
      await page.waitFor(`${CALLS} === 2 && ${SUBMITS} === 2`);
      await page.evaluate("globalThis.pendingSubmit.release()");
    });
  }
});
