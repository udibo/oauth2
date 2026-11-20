import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { readFileSync, writeFileSync } from "node:fs";
import { connect, createServer, type AddressInfo } from "node:net";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { chromium, expect } from "@playwright/test";

import { parseDevIdpConfig } from "../src/cli/idp/config.ts";
import { startDevIdentityProvider } from "../src/cli/idp/server.ts";
import { generateSigningKey } from "../src/server/signing-keys.ts";

/** Exercises the published quickstart app from the installed npm smoke consumer with a different-site issuer. */
export async function checkHostedQuickstart(
  consumerDir: string,
): Promise<void> {
  const guide = readFileSync(
    new URL("../docs/quickstart.md", import.meta.url),
    "utf8",
  );
  const app = /^```ts\r?\n([\s\S]*?)\r?\n```$/m.exec(guide)?.[1];
  const config = /^```json\r?\n([\s\S]*?)\r?\n```$/m.exec(guide)?.[1];
  if (!app || !config)
    throw new Error("Missing app.ts or idp.json in the quickstart");
  writeFileSync(join(consumerDir, "app.ts"), app);
  writeFileSync(join(consumerDir, "idp.json"), config);

  // Reserve the callback origin before registering the client and starting app.ts.
  let appPort: number;
  await using front = createServer((socket) => {
    const upstream = connect(appPort, "127.0.0.1");
    socket.on("error", () => upstream.destroy());
    upstream.on("error", () => socket.destroy());
    socket.pipe(upstream).pipe(socket);
  });
  front.listen(0, "localhost");
  await once(front, "listening");
  const origin = `http://localhost:${(front.address() as AddressInfo).port}`;
  const callback = `${origin}/auth/callback`;
  const client = {
    id: "hosted-app",
    secret: randomUUID(),
    redirectUris: [callback],
  };
  const idp = await startDevIdentityProvider({
    config: parseDevIdpConfig({
      port: 0,
      hostname: "127.0.0.1",
      users: [
        {
          username: "reader",
          password: "local-password",
          claims: { name: "Hosted Reader" },
        },
      ],
      clients: [client],
    }),
    signingKey: await generateSigningKey(),
  });

  try {
    const child = spawn(process.execPath, ["app.ts"], {
      cwd: consumerDir,
      env: {
        ...process.env,
        PORT: "0",
        AUTH_ISSUER: idp.issuer,
        AUTH_CLIENT_ID: client.id,
        AUTH_CLIENT_SECRET: client.secret,
        AUTH_CALLBACK_URL: callback,
      },
      stdio: ["ignore", "pipe", "inherit"],
    });
    const exited = once(child, "close");
    try {
      const output = createInterface({ input: child.stdout });
      const [banner] = await Promise.race([
        once(output, "line", { signal: AbortSignal.timeout(15_000) }),
        exited.then(() => {
          throw new Error("Quickstart exited before listening");
        }),
      ]);
      appPort = Number(
        new URL(String(banner).replace("Listening on ", "")).port,
      );
      await using browser = await chromium.launch();
      for (const path of ["/", "/dashboard"]) {
        await using context = await browser.newContext({
          javaScriptEnabled: false,
        });
        context.setDefaultTimeout(10_000);
        const page = await context.newPage();
        await page.goto(origin + path);
        if (path === "/")
          await page.getByRole("link", { name: "Sign in" }).click();
        await expect(page).toHaveURL((url) => url.origin === idp.issuer);
        await page.getByLabel("Username").fill("reader");
        await page.getByLabel("Password").fill("local-password");
        await Promise.all([
          page
            .waitForResponse(
              (response) =>
                response.url() === origin + "/dashboard" &&
                response.request().isNavigationRequest(),
            )
            .then((response) =>
              expect(
                response.status(),
                "the first dashboard response after sign-in",
              ).toBe(200),
            ),
          page.getByRole("button", { name: "Sign in", exact: true }).click(),
        ]);
        await expect(
          page.getByRole("heading", { name: "Hello, Hosted Reader" }),
        ).toBeVisible();
        await expect(page).toHaveURL(origin + "/dashboard");
        const cookies = await context.cookies(origin);
        expect(
          cookies.find((cookie) => cookie.name === "oauth2_session"),
        ).toMatchObject({ httpOnly: true, sameSite: "Strict" });
        await page.getByRole("link", { name: "Sign out" }).click();
        await expect(page.getByRole("link", { name: "Sign in" })).toBeVisible();
        await expect(page).toHaveURL(origin + "/");
        const session = await page.request.get(origin + "/auth/session", {
          headers: { "x-csrf": "1" },
        });
        expect(await session.json()).toMatchObject({ isAuthenticated: false });
      }
    } finally {
      child.kill();
      await exited;
    }
  } finally {
    await idp.shutdown();
  }
}
