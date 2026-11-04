import { IncomingMessage } from "node:http";
import { Socket } from "node:net";

import { describe, expect, it } from "vitest";

import { type ExpressRequestLike, toFetchRequest } from "./_common.ts";

function nodeRequest(
  host: string | undefined,
  url: string,
): ExpressRequestLike {
  const req: ExpressRequestLike = new IncomingMessage(new Socket());
  req.method = "GET";
  req.url = url;
  if (host !== undefined) {
    req.headers.host = host;
    req.rawHeaders.push("Host", host);
  }
  return req;
}

describe("toFetchRequest on a request without Express's fields", () => {
  it("builds the URL from Host and the target", () => {
    expect(
      toFetchRequest(nodeRequest("App.Example:8080", "/a?b=c"), "stream").url,
    ).toBe("http://app.example:8080/a?b=c");
  });

  it("accepts a Host that names the default port", () => {
    expect(
      toFetchRequest(nodeRequest("app.example:80", "/"), "stream").url,
    ).toBe("http://app.example/");
  });

  it.each([
    "app.example/evil",
    "app.example#x",
    "app.example?x",
    "b.exa\tmple",
    "app.example@evil.example",
  ])("refuses the Host %j", (host) => {
    expect(() => toFetchRequest(nodeRequest(host, "/"), "stream")).toThrow(
      "The Host header is not a plain host and port.",
    );
  });

  it("refuses a request with no Host", () => {
    expect(() => toFetchRequest(nodeRequest(undefined, "/"), "stream")).toThrow(
      "The request has no Host header.",
    );
  });
});
