import { describe, expect, it } from "vitest";

import { DEMO_CLIENT } from "./server.ts";

describe("demo client registration", () => {
  it("registers the redirect URIs of this app and both companion examples", () => {
    expect(DEMO_CLIENT.redirectUris).toEqual([
      "http://localhost:8001/auth/callback",
      "http://localhost:8002/dev/callback",
      "http://localhost:8003/auth/callback",
    ]);
  });
});
