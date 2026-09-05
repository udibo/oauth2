import {
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { encodeBase64Url } from "@std/encoding/base64url";
import { describe, it } from "@std/testing/bdd";

import { MemoryDiscoveryCache } from "../../client/discovery-cache.ts";
import { ExternalAuthError } from "./errors.ts";
import { ExternalAuthFlow } from "./flow.ts";
import { oidcProvider, type OidcProviderOptions } from "./oidc.ts";

const clientId = "web-app";
const clientSecret = "secret";
const redirectUri = "https://app.example/cb";

function discoveryStub(issuer: string): typeof fetch {
  return (input) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url.endsWith("/.well-known/oauth-authorization-server")) {
      return Promise.resolve(new Response("Not Found", { status: 404 }));
    }
    if (url.endsWith("/.well-known/openid-configuration")) {
      return Promise.resolve(
        Response.json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
        }),
      );
    }
    return Promise.resolve(new Response("Not Found", { status: 404 }));
  };
}

function segment(value: unknown): string {
  return encodeBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function tokenStub(issuer: string, claims: Record<string, unknown>) {
  const discovery = discoveryStub(issuer);
  const context = { nonce: undefined as string | undefined };
  const fetchStub: typeof fetch = (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== `${issuer}/token`) return discovery(input, init);
    const payload = segment({
      iss: issuer,
      aud: clientId,
      sub: "sso-1",
      exp: Math.floor(Date.now() / 1000) + 3600,
      nonce: context.nonce,
      ...claims,
    });
    return Promise.resolve(Response.json({
      token_type: "Bearer",
      access_token: "sso-access-token",
      expires_in: 3600,
      id_token: `${segment({ alg: "ES256", typ: "JWT" })}.${payload}.sig`,
    }));
  };
  return { fetch: fetchStub, context };
}

function signIn(
  claims: Record<string, unknown>,
  config?: Pick<OidcProviderOptions, "azp">,
): Promise<Awaited<ReturnType<ExternalAuthFlow["finish"]>>> {
  const issuer = "https://sso.example";
  const stub = tokenStub(issuer, claims);
  const flow = new ExternalAuthFlow({
    provider: oidcProvider({
      issuer,
      clientId,
      clientSecret,
      fetch: stub.fetch,
      ...config,
    }),
  });
  return flow.start({ redirectUri }).then(({ transient }) => {
    stub.context.nonce = transient.nonce;
    return flow.finish({
      params: new URLSearchParams({ code: "sso-code", state: transient.state }),
      transient,
    });
  });
}

describe("oidcProvider", () => {
  it("rejects a non-https issuer at construction", () => {
    const error = assertThrows(
      () =>
        oidcProvider({
          issuer: "http://sso.example",
          clientId,
          clientSecret,
        }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "https");
  });

  it("allows an http issuer on localhost for development", () => {
    const provider = oidcProvider({
      issuer: "http://localhost:9000",
      clientId,
      clientSecret,
    });
    assertEquals(provider.id, "oidc");
  });

  it("constructs a public provider when clientSecret is omitted", () => {
    const provider = oidcProvider({ issuer: "https://sso.example", clientId });
    assertEquals(provider.id, "oidc");
  });

  it("constructs a public provider when clientSecret is explicitly undefined", () => {
    const config: OidcProviderOptions = {
      issuer: "https://sso.example",
      clientId,
      clientSecret: undefined,
    };
    assertEquals(oidcProvider(config).id, "oidc");
  });

  it("authenticates a secretless provider with a body client_id, no Authorization", async () => {
    const issuer = "https://sso.example";
    let tokenInit: RequestInit | undefined;
    const provider = oidcProvider({
      issuer,
      clientId,
      fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url === `${issuer}/token`) {
          tokenInit = init;
          return Promise.resolve(
            Response.json({ access_token: "at", token_type: "Bearer" }),
          );
        }
        return discoveryStub(issuer)(input, init);
      }) as typeof fetch,
    });
    const flow = new ExternalAuthFlow({ provider });
    const { transient } = await flow.start({ redirectUri });

    await assertRejects(() =>
      flow.finish({
        params: new URLSearchParams({ code: "c", state: transient.state }),
        transient,
      })
    );

    const headers = new Headers(tokenInit?.headers);
    assertEquals(
      headers.has("Authorization"),
      false,
      "a secretless provider must not send Basic credentials",
    );
    assertEquals(
      new URLSearchParams(tokenInit?.body as string).get("client_id"),
      clientId,
    );
  });

  it("rejects a discovery document whose issuer differs from the configured issuer", async () => {
    const provider = oidcProvider({
      issuer: "https://real.example",
      clientId,
      clientSecret,
      fetch: discoveryStub("https://evil.example"),
    });
    const flow = new ExternalAuthFlow({ provider });

    const error = await assertRejects(
      () => flow.start({ redirectUri }),
      ExternalAuthError,
    );
    assertEquals(error.code, "configuration");
    assertStringIncludes(error.message, "https://evil.example");
    assertStringIncludes(error.message, "https://real.example");
  });

  it("tolerates a trailing-slash difference between configured and document issuer", async () => {
    const provider = oidcProvider({
      issuer: "https://real.example/",
      clientId,
      clientSecret,
      fetch: discoveryStub("https://real.example"),
    });
    const flow = new ExternalAuthFlow({ provider });

    const { url } = await flow.start({ redirectUri });
    assertStringIncludes(url, "https://real.example/authorize");
  });

  it("shares one discovery fetch across connectors given the same cache", async () => {
    const issuer = "https://real.example";
    let discoveries = 0;
    const stub = discoveryStub(issuer);
    const countingFetch: typeof fetch = (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/openid-configuration")) discoveries++;
      return stub(input, init);
    };
    const discoveryCache = new MemoryDiscoveryCache();
    const startFlow = () =>
      new ExternalAuthFlow({
        provider: oidcProvider({
          issuer,
          clientId,
          clientSecret,
          fetch: countingFetch,
          discoveryCache,
        }),
      }).start({ redirectUri });

    await startFlow();
    await startFlow();

    assertEquals(discoveries, 1);
  });

  it("re-discovers per connector without a shared cache", async () => {
    const issuer = "https://real.example";
    let discoveries = 0;
    const stub = discoveryStub(issuer);
    const countingFetch: typeof fetch = (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/.well-known/openid-configuration")) discoveries++;
      return stub(input, init);
    };
    const startFlow = () =>
      new ExternalAuthFlow({
        provider: oidcProvider({
          issuer,
          clientId,
          clientSecret,
          fetch: countingFetch,
        }),
      }).start({ redirectUri });

    await startFlow();
    await startFlow();

    assertEquals(discoveries, 2);
  });

  it("rejects an id_token whose azp names a different client", async () => {
    const error = await assertRejects(
      () => signIn({ azp: "another-client" }),
      ExternalAuthError,
    );
    assertEquals(error.code, "provider_error");
    assertStringIncludes(error.message, "azp");
  });

  it("accepts a foreign azp when the config opts out of the check", async () => {
    const profile = await signIn({ azp: "another-client" }, { azp: "ignore" });
    assertEquals(profile.subject, "sso-1");
  });
});
