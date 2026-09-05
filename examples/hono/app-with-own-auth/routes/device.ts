/**
 * Device-code verification page (RFC 8628).
 *
 * Mounted at `/device` by `main.ts`; the paths below are relative. The
 * browser flow for the device authorization grant is:
 *
 *   1. The device asks the auth server for a `device_code` and
 *      `user_code` via `POST /oauth2/device_authorization`.
 *   2. The user opens `verification_uri` (this page) on a separate
 *      device, types the `user_code`, signs in, and approves the
 *      request.
 *   3. The original device polls `POST /oauth2/token` with the device
 *      code; once the user approves, the token is issued.
 *
 * `GET /` renders a form for entering the user code; `POST /`
 * validates the code and (if the user is authenticated) shows a
 * second-step consent button that approves or denies the device
 * authorization.
 *
 * @module
 */

import { Hono } from "hono";

import { escapeHtml } from "../html.ts";
import { deviceService, userService } from "../oauth2/server.ts";
import { readSessionUserId } from "../sessions.ts";

const app = new Hono();

app.get("/", (c) => {
  const userId = readSessionUserId(c);
  if (!userId) {
    const userCode = c.req.query("user_code") ?? "";
    const returnTo = userCode
      ? `/device?user_code=${encodeURIComponent(userCode)}`
      : "/device";
    return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
  }
  const error = c.req.query("error");
  return c.html(entryPage({ userCode: c.req.query("user_code"), error }));
});

app.post("/", async (c) => {
  const form = await c.req.formData();
  const userCode = String(form.get("user_code") ?? "").trim();
  const decision = String(form.get("decision") ?? "");

  const userId = readSessionUserId(c);
  if (!userId) {
    return c.redirect(
      `/login?return_to=${encodeURIComponent(`/device?user_code=${userCode}`)}`,
    );
  }
  const user = await userService.get(userId);
  if (!user) {
    return c.redirect(
      `/login?return_to=${encodeURIComponent(`/device?user_code=${userCode}`)}`,
    );
  }

  const auth = await deviceService.getByUserCode(userCode);
  if (!auth) {
    return c.html(entryPage({ userCode, error: "Unknown code." }), 400);
  }

  if (!decision) {
    return c.html(approvalPage({ userCode, clientId: auth.client.id }));
  }

  if (decision === "approve") {
    await deviceService.approve(auth, user);
    return c.html(resultPage({ approved: true }));
  }
  await deviceService.deny(auth);
  return c.html(resultPage({ approved: false }));
});

export default app;

function entryPage(
  options: { userCode?: string; error?: string },
): string {
  const code = escapeHtml(options.userCode ?? "");
  const err = options.error
    ? `<p style="color:red">${escapeHtml(options.error)}</p>`
    : "";
  return `<!doctype html>
<title>Authorize a device</title>
<h1>Authorize a device</h1>
${err}
<p>Enter the code shown on your device.</p>
<form method="post" action="/device">
  <input name="user_code" required autofocus value="${code}">
  <button type="submit">Continue</button>
</form>
<p style="font-size:smaller;color:#666">
  The <code>user_code</code> identifies the device asking for access; you
  already signed in, so any approval here will issue the token to your
  account.
</p>`;
}

function approvalPage(
  options: { userCode: string; clientId: string },
): string {
  return `<!doctype html>
<title>Authorize device</title>
<h1>Authorize <em>${escapeHtml(options.clientId)}</em>?</h1>
<p>Code: <code>${escapeHtml(options.userCode)}</code></p>
<form method="post" action="/device">
  <input type="hidden" name="user_code" value="${escapeHtml(options.userCode)}">
  <button name="decision" value="approve" type="submit">Approve</button>
  <button name="decision" value="deny" type="submit">Deny</button>
</form>`;
}

function resultPage(options: { approved: boolean }): string {
  const message = options.approved
    ? "Device approved. You can return to the device."
    : "Device denied.";
  return `<!doctype html>
<title>Done</title>
<h1>${message}</h1>`;
}
