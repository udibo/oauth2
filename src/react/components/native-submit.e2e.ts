/**
 * The drop-in forms submitted before any JavaScript runs, in headless
 * Chromium: server-rendered markup, scripts disabled, no `action` or `method`
 * passed. That is the page a person sees while the bundle is slow or after it
 * failed to load.
 *
 * Not `*.test.ts`, so `pnpm test` does not pick it up; it runs as
 * `pnpm test:browser`.
 *
 * @module
 */

import { fileURLToPath } from "node:url";
import { expect, test as base } from "@playwright/test";
import { createServer } from "vite";

import { serve } from "../../_test_server.ts";

const FORMS = [
  { name: "SignInForm", field: "password" },
  { name: "SignUpForm", field: "password" },
  { name: "RequestPasswordResetForm", field: "email" },
  { name: "ResetPasswordForm", field: "password" },
  { name: "MfaChallengeForm", field: "code" },
  { name: "MfaEnrollmentForm", field: "code" },
] as const;

const SECRET = "s3cret-value-9137";

const PAGE_ENTRY = fileURLToPath(
  new URL("./_test_native_submit_page.tsx", import.meta.url),
);

type RenderPage = (name: string) => string;

const test = base.extend<object, { renderPage: RenderPage }>({
  renderPage: [
    // oxlint-disable-next-line no-empty-pattern -- Playwright reads the fixture dependencies from this pattern
    async ({}, use) => {
      const vite = await createServer({
        configFile: false,
        logLevel: "silent",
        appType: "custom",
        server: { middlewareMode: true, hmr: false, ws: false },
        oxc: { jsx: { runtime: "automatic" } },
      });
      try {
        const page = (await vite.ssrLoadModule(PAGE_ENTRY)) as {
          renderPage: RenderPage;
        };
        await use(page.renderPage);
      } finally {
        await vite.close();
      }
    },
    { scope: "worker" },
  ],
});

test.use({ javaScriptEnabled: false });

test.describe("a submit before hydration in a real browser", () => {
  for (const form of FORMS) {
    test(`${form.name} posts its fields in the body, never the URL`, async ({
      page,
      renderPage,
    }) => {
      const html = renderPage(form.name);
      const received: { method: string; url: string; body: string }[] = [];
      await using server = await serve(async (request) => {
        received.push({
          method: request.method,
          url: request.url,
          body: await request.text(),
        });
        return new Response(html, {
          headers: { "content-type": "text/html" },
        });
      });

      await page.goto(`${server.origin}/sign-in`);
      await page.locator(`input[name="${form.field}"]`).fill(SECRET);
      await Promise.all([
        page.waitForRequest((request) => request.isNavigationRequest()),
        page.locator("[data-oauth2-submit]").click(),
      ]);
      await page.waitForLoadState();

      const submitted = received.at(-1)!;
      expect(submitted.method).toBe("POST");
      expect(submitted.url).toBe(`${server.origin}/sign-in`);
      expect(new URLSearchParams(submitted.body).get(form.field)).toBe(SECRET);
      expect(page.url()).not.toContain(SECRET);
    });
  }
});
