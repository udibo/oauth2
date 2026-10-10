/**
 * The drop-in forms' pending submit, driven in headless Chromium.
 *
 * A pending submit button carries `aria-disabled` rather than `disabled`
 * because Chromium moves focus from a focused element to `<body>` the moment it
 * becomes disabled. jsdom has no such focus fixup, so `pending-submit.test.tsx`
 * passes against either attribute; only a real engine shows the difference.
 *
 * Not `*.test.ts`, so `pnpm test` does not pick it up; it runs as
 * `pnpm test:browser`.
 *
 * @module
 */

import { fileURLToPath } from "node:url";
import {
  expect,
  type Locator,
  type Page,
  test as base,
} from "@playwright/test";
import { build } from "vite";

import { serve } from "../../_test_server.ts";

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

const PAGE_ENTRY = fileURLToPath(
  new URL("./_test_pending_submit_page.tsx", import.meta.url),
);
const HTML =
  '<!doctype html><html lang="en"><body><div id="root"></div>' +
  '<script type="module" src="/page.js"></script></body></html>';

async function bundlePage(): Promise<string> {
  const result = await build({
    configFile: false,
    logLevel: "silent",
    define: { "process.env.NODE_ENV": '"development"' },
    oxc: { jsx: { runtime: "automatic" } },
    build: {
      write: false,
      minify: false,
      lib: { entry: PAGE_ENTRY, formats: ["es"], fileName: "page" },
    },
  });
  const outputs = Array.isArray(result) ? result : [result];
  const chunk = outputs
    .flatMap((output) => ("output" in output ? output.output : []))
    .find((file) => file.type === "chunk" && file.isEntry);
  if (chunk?.type !== "chunk") throw new Error("the page bundle has no entry");
  return chunk.code;
}

const test = base.extend<object, { origin: string }>({
  origin: [
    // oxlint-disable-next-line no-empty-pattern -- Playwright reads the fixture dependencies from this pattern
    async ({}, use) => {
      const script = await bundlePage();
      const server = await serve((request) => {
        const { pathname } = new URL(request.url);
        if (pathname === "/page.js") {
          return new Response(script, {
            headers: { "content-type": "text/javascript" },
          });
        }
        if (pathname === "/") {
          return new Response(HTML, {
            headers: { "content-type": "text/html" },
          });
        }
        return new Response("Not found", { status: 404 });
      });
      try {
        await use(server.origin);
      } finally {
        await server.shutdown();
      }
    },
    { scope: "worker" },
  ],
});

function submitButton(page: Page): Locator {
  return page.locator("[data-oauth2-submit]");
}

function pendingSubmit<T>(page: Page, read: string): Promise<T> {
  return page.evaluate(
    (key) =>
      (globalThis as unknown as Record<string, Record<string, T>>)
        .pendingSubmit![key] as T,
    read,
  );
}

async function afterNextPaint(page: Page): Promise<void> {
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
      ),
  );
}

test.describe("a pending submit in a real browser", () => {
  for (const form of FORMS) {
    test(`${form.name} keeps focus on its pending button and submits once`, async ({
      page,
      origin,
    }) => {
      const button = submitButton(page);
      await page.goto(`${origin}/?form=${form.name}`);
      await expect(button).toHaveText(form.label);

      await button.focus();
      await page.keyboard.press("Enter");
      await expect(button).toHaveText(form.pendingLabel);

      await expect(
        button,
        "a pending submit must keep focus; a natively disabled one hands it to <body>",
      ).toBeFocused();
      await expect(button).toHaveAttribute("aria-disabled", "true");
      expect(
        await button.evaluate((el) => (el as HTMLButtonElement).disabled),
      ).toBe(false);
      expect(await pendingSubmit<number>(page, "calls")).toBe(1);

      await page.keyboard.press("Enter");
      await page.keyboard.press(" ");
      await button.click({ force: true });
      await afterNextPaint(page);
      expect(
        await pendingSubmit<number>(page, "calls"),
        "Enter, Space and a click on a pending submit must not submit again",
      ).toBe(1);
      expect(
        await pendingSubmit<number>(page, "submits"),
        "the pending button must cancel activation, so its form never posts again",
      ).toBe(1);
      await expect(button).toBeFocused();

      await page.evaluate(() =>
        (
          globalThis as unknown as { pendingSubmit: { release(): void } }
        ).pendingSubmit.release(),
      );
      await expect(button).toHaveText(form.label);
      await expect(button).not.toHaveAttribute("aria-disabled", /.*/);

      await button.focus();
      await page.keyboard.press(" ");
      await expect.poll(() => pendingSubmit<number>(page, "calls")).toBe(2);
      expect(await pendingSubmit<number>(page, "submits")).toBe(2);
      await page.evaluate(() =>
        (
          globalThis as unknown as { pendingSubmit: { release(): void } }
        ).pendingSubmit.release(),
      );
    });
  }
});
