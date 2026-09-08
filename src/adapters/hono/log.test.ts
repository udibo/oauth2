import { describe, it } from "@std/testing/bdd";
import { assert, assertEquals, assertFalse } from "@std/assert";
import { stub } from "@std/testing/mock";
import { Hono } from "hono";

import { redactedRequestTarget, requestLogger } from "./log.ts";

describe("redactedRequestTarget", () => {
  it("returns the pathname untouched when there is no query", () => {
    assertEquals(
      redactedRequestTarget("https://app.example.com/reset-password"),
      "/reset-password",
    );
  });

  it("keeps the parameter name and replaces its value", () => {
    const secret = crypto.randomUUID();
    assertEquals(
      redactedRequestTarget(
        `https://app.example.com/verify-email?token=${secret}`,
      ),
      "/verify-email?token=[redacted]",
    );
  });

  it("redacts every parameter, not only the one named token", () => {
    assertEquals(
      redactedRequestTarget(
        `https://app.example.com/signin-link?token=${crypto.randomUUID()}&redirect=/profile`,
      ),
      "/signin-link?token=[redacted]&redirect=[redacted]",
    );
  });

  it("redacts a value nested inside another parameter's value", () => {
    const secret = crypto.randomUUID();
    const nested = encodeURIComponent(`/administrator-invite?token=${secret}`);
    const target = redactedRequestTarget(
      `https://app.example.com/sign-in?redirect=${nested}`,
    );
    assertFalse(
      target.includes(secret),
      "a token carried through a redirect parameter is still a token",
    );
    assertEquals(target, "/sign-in?redirect=[redacted]");
  });

  it("keeps one entry per repeat so the shape of the request survives", () => {
    assertEquals(
      redactedRequestTarget(
        "https://app.example.com/identity/t/audit?eventType=auth&eventType=admin",
      ),
      "/identity/t/audit?eventType=[redacted]&eventType=[redacted]",
    );
  });

  it("redacts a valueless parameter rather than echoing it", () => {
    assertEquals(
      redactedRequestTarget("https://app.example.com/users?includeDeleted"),
      "/users?includeDeleted=[redacted]",
    );
  });

  it("encodes a parameter name so it cannot forge a second log line", () => {
    const target = redactedRequestTarget(
      "https://app.example.com/?%0A%3C--%20GET%20%2Fadmin=1",
    );
    assertFalse(
      target.includes("\n"),
      "a decoded newline in a parameter name would split the log line",
    );
    assertEquals(target, "/?%0A%3C--%20GET%20%2Fadmin=[redacted]");
  });

  it("drops the origin, so a host is never confused for a path", () => {
    assertEquals(
      redactedRequestTarget("https://tenant.example.com/profile?tab=security"),
      "/profile?tab=[redacted]",
    );
  });
});

describe("requestLogger", () => {
  function captured(): { lines: string[]; app: Hono } {
    const lines: string[] = [];
    const app = new Hono();
    app.use(requestLogger((line) => lines.push(line)));
    app.get("/reset-password", (c) => c.text("ok"));
    app.get("/verify-email", (c) => c.redirect("/sign-in?verify=invalid"));
    return { lines, app };
  }

  it("logs the request and the response without the reset token", async () => {
    const secret = crypto.randomUUID();
    const { lines, app } = captured();

    const res = await app.request(
      `https://app.example.com/reset-password?token=${secret}`,
    );
    assertEquals(res.status, 200);
    await res.text();

    assertFalse(
      lines.some((line) => line.includes(secret)),
      `the reset token reached the log: ${lines.join(" | ")}`,
    );
    assertEquals(lines[0], "<-- GET /reset-password?token=[redacted]");
    assert(
      lines[1]?.startsWith("--> GET /reset-password?token=[redacted] 200 "),
      `the response line must carry the same redacted target: ${lines[1]}`,
    );
  });

  it("logs the request and the response without the verification token", async () => {
    const secret = crypto.randomUUID();
    const { lines, app } = captured();

    const res = await app.request(
      `https://app.example.com/verify-email?token=${secret}`,
    );
    assertEquals(res.status, 302);
    await res.body?.cancel();

    assertFalse(
      lines.some((line) => line.includes(secret)),
      `the verification token reached the log: ${lines.join(" | ")}`,
    );
    assertEquals(lines[0], "<-- GET /verify-email?token=[redacted]");
    assert(
      lines[1]?.startsWith("--> GET /verify-email?token=[redacted] 302 "),
      `the response line must carry the same redacted target: ${lines[1]}`,
    );
  });

  it("names the method so a POST is distinguishable from a GET", async () => {
    const lines: string[] = [];
    const app = new Hono();
    app.use(requestLogger((line) => lines.push(line)));
    app.post("/reset-password", (c) => c.text("ok"));

    const res = await app.request("https://app.example.com/reset-password", {
      method: "POST",
    });
    await res.text();

    assertEquals(lines[0], "<-- POST /reset-password");
  });

  it("defaults to console.log, resolved per line so a stub still sees it", async () => {
    const secret = crypto.randomUUID();
    const lines: string[] = [];
    const app = new Hono();
    app.use(requestLogger());
    app.get("/reset-password", (c) => c.text("ok"));

    using _log = stub(console, "log", (...args: unknown[]) => {
      lines.push(args.join(" "));
    });

    const res = await app.request(
      `https://app.example.com/reset-password?token=${secret}`,
    );
    await res.text();

    assertEquals(lines[0], "<-- GET /reset-password?token=[redacted]");
  });
});
