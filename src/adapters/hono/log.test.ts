import { setTimeout } from "node:timers/promises";

import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";

import { redactedRequestTarget, requestLogger } from "./log.ts";

describe("redactedRequestTarget", () => {
  it("returns the pathname untouched when there is no query", () => {
    expect(
      redactedRequestTarget("https://app.example.com/reset-password"),
    ).toStrictEqual("/reset-password");
  });

  it("keeps the parameter name and replaces its value", () => {
    const secret = crypto.randomUUID();
    expect(
      redactedRequestTarget(
        `https://app.example.com/verify-email?token=${secret}`,
      ),
    ).toStrictEqual("/verify-email?token=[redacted]");
  });

  it("redacts every parameter, not only the one named token", () => {
    expect(
      redactedRequestTarget(
        `https://app.example.com/signin-link?token=${crypto.randomUUID()}&redirect=/profile`,
      ),
    ).toStrictEqual("/signin-link?token=[redacted]&redirect=[redacted]");
  });

  it("redacts a value nested inside another parameter's value", () => {
    const secret = crypto.randomUUID();
    const nested = encodeURIComponent(`/administrator-invite?token=${secret}`);
    const target = redactedRequestTarget(
      `https://app.example.com/sign-in?redirect=${nested}`,
    );
    expect(
      target.includes(secret),
      "a token carried through a redirect parameter is still a token",
    ).toBeFalsy();
    expect(target).toStrictEqual("/sign-in?redirect=[redacted]");
  });

  it("keeps one entry per repeat so the shape of the request survives", () => {
    expect(
      redactedRequestTarget(
        "https://app.example.com/identity/t/audit?eventType=auth&eventType=admin",
      ),
    ).toStrictEqual(
      "/identity/t/audit?eventType=[redacted]&eventType=[redacted]",
    );
  });

  it("redacts a valueless parameter rather than echoing it", () => {
    expect(
      redactedRequestTarget("https://app.example.com/users?includeDeleted"),
    ).toStrictEqual("/users?includeDeleted=[redacted]");
  });

  it("encodes a parameter name so it cannot forge a second log line", () => {
    const target = redactedRequestTarget(
      "https://app.example.com/?%0A%3C--%20GET%20%2Fadmin=1",
    );
    expect(
      target.includes("\n"),
      "a decoded newline in a parameter name would split the log line",
    ).toBeFalsy();
    expect(target).toStrictEqual("/?%0A%3C--%20GET%20%2Fadmin=[redacted]");
  });

  it("drops the origin, so a host is never confused for a path", () => {
    expect(
      redactedRequestTarget("https://tenant.example.com/profile?tab=security"),
    ).toStrictEqual("/profile?tab=[redacted]");
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

  it("logs one line per request, without the reset token", async () => {
    const secret = crypto.randomUUID();
    const { lines, app } = captured();

    const res = await app.request(
      `https://app.example.com/reset-password?token=${secret}`,
    );
    expect(res.status).toStrictEqual(200);
    await res.text();

    expect(
      lines.some((line) => line.includes(secret)),
      `the reset token reached the log: ${lines.join(" | ")}`,
    ).toBeFalsy();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^--> GET \/reset-password\?token=\[redacted\] 200 \d+ms$/,
    );
  });

  it("logs the response status without the verification token", async () => {
    const secret = crypto.randomUUID();
    const { lines, app } = captured();

    const res = await app.request(
      `https://app.example.com/verify-email?token=${secret}`,
    );
    expect(res.status).toStrictEqual(302);
    await res.body?.cancel();

    expect(
      lines.some((line) => line.includes(secret)),
      `the verification token reached the log: ${lines.join(" | ")}`,
    ).toBeFalsy();
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^--> GET \/verify-email\?token=\[redacted\] 302 \d+ms$/,
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

    expect(lines[0]).toMatch(/^--> POST \/reset-password 200 \d+ms$/);
  });

  it("defaults to console.log, resolved per line so a stub still sees it", async () => {
    const secret = crypto.randomUUID();
    const lines: string[] = [];
    const app = new Hono();
    app.use(requestLogger());
    app.get("/reset-password", (c) => c.text("ok"));

    using _log = vi
      .spyOn(console, "log")
      .mockImplementation((...args: unknown[]) => {
        lines.push(args.join(" "));
      });

    const res = await app.request(
      `https://app.example.com/reset-password?token=${secret}`,
    );
    await res.text();

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^--> GET \/reset-password\?token=\[redacted\] /);
  });

  it("folds the requests a handler dispatches in process into its own line, in completion order", async () => {
    const { lines, app } = captured();
    app.get("/api/shell", (c) => c.json({}));
    app.get("/api/missing", (c) => c.json({}, 404));
    app.get("/page", async (c) => {
      await app.fetch(new Request("https://app.example.com/api/shell"));
      await app.fetch(new Request("https://app.example.com/api/missing"));
      return c.html("<p>page</p>");
    });

    await (await app.request("https://app.example.com/page")).text();

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^--> GET \/page 200 \d+ms \[GET \/api\/shell 200 \d+ms, GET \/api\/missing 404 \d+ms\]$/,
    );
  });

  it("redacts the query values of every request folded into a line", async () => {
    const secret = crypto.randomUUID();
    const { lines, app } = captured();
    app.get("/api/verify", (c) => c.json({}));
    app.get("/confirm", async (c) => {
      await app.fetch(
        new Request(
          `https://app.example.com/api/verify?token=${secret}&token=again`,
        ),
      );
      return c.text("confirmed");
    });

    await (
      await app.request(`https://app.example.com/confirm?token=${secret}`)
    ).text();

    expect(lines.join("\n")).not.toContain(secret);
    expect(lines[0]).toMatch(
      /^--> GET \/confirm\?token=\[redacted\] 200 \d+ms \[GET \/api\/verify\?token=\[redacted\]&token=\[redacted\] 200 \d+ms\]$/,
    );
  });

  it("gives an in-process request that outlives the outer response a line of its own", async () => {
    const { lines, app } = captured();
    app.get("/api/slow", async (c) => {
      await setTimeout(20);
      return c.json({});
    });
    let streamed: Promise<Response> | undefined;
    app.get("/page", (c) => {
      streamed = Promise.resolve(
        app.fetch(new Request("https://app.example.com/api/slow")),
      );
      return c.text("shell");
    });

    await (await app.request("https://app.example.com/page")).text();
    await (await streamed)?.text();

    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^--> GET \/page 200 \d+ms$/);
    expect(lines[1]).toMatch(/^--> \(in-process\) GET \/api\/slow 200 \d+ms$/);
  });

  it("keeps concurrent requests' in-process calls apart", async () => {
    const { lines, app } = captured();
    app.get("/api/:name", (c) => c.json({}));
    app.get("/page/:name", async (c) => {
      await setTimeout(5);
      await app.fetch(
        new Request(`https://app.example.com/api/${c.req.param("name")}`),
      );
      return c.text("page");
    });

    await Promise.all([
      app.request("https://app.example.com/page/one"),
      app.request("https://app.example.com/page/two"),
    ]);

    expect(lines).toHaveLength(2);
    expect(lines.find((line) => line.startsWith("--> GET /page/one "))).toMatch(
      /\[GET \/api\/one 200 \d+ms\]$/,
    );
    expect(lines.find((line) => line.startsWith("--> GET /page/two "))).toMatch(
      /\[GET \/api\/two 200 \d+ms\]$/,
    );
  });
});
