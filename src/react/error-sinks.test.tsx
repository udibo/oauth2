// deno-lint-ignore-file no-window require-await -- jsdom provides `window`; `act(async …)` needs the async signature
import { cleanupAfterEach } from "./_test_setup.ts";

import { assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { render, screen } from "@testing-library/react";
import { act, type ReactNode } from "react";

import {
  type BaseLoginOptions,
  DirectClient,
  type LoginRedirect,
  type LogoutOptions,
  type LogoutRedirect,
  MemoryTokenStorage,
  OAuth2ClientBase,
  type SessionState,
  SIGNED_OUT,
  type UserInfoClaims,
} from "../client/mod.ts";
import { base64urlEncode } from "../utils/crypto.ts";

import { OAuth2Callback } from "./callback.tsx";
import { OAuth2Provider } from "./provider.tsx";
import { useOAuth2 } from "./use-oauth2.ts";

cleanupAfterEach();

const AUTHORIZE_URL = "https://auth.example/authorize";
const TOKEN_URL = "https://auth.example/token";

class ProbeRejectingClient extends OAuth2ClientBase {
  constructor() {
    super();
  }

  login(_options?: BaseLoginOptions): Promise<LoginRedirect> {
    return Promise.resolve({ url: "/login" });
  }

  logout(_options?: LogoutOptions): Promise<LogoutRedirect> {
    return Promise.resolve({});
  }

  getUser(): Promise<UserInfoClaims | null> {
    return Promise.resolve(null);
  }

  getSession(): Promise<SessionState> {
    return Promise.reject(new TypeError("probe exploded"));
  }

  renewSession(): Promise<SessionState> {
    return Promise.resolve(SIGNED_OUT);
  }

  fetch(): Promise<Response> {
    return Promise.resolve(new Response(null, { status: 204 }));
  }
}

function ErrorCodeProbe(): ReactNode {
  const { error } = useOAuth2();
  return (
    <span data-testid="code">{error ? error.extensions.error : "none"}</span>
  );
}

function directClientWithIdToken(idToken: string): DirectClient {
  const tokenStorage = new MemoryTokenStorage();
  tokenStorage.set({ accessToken: "at", tokenType: "Bearer", idToken });
  return new DirectClient({
    clientId: "spa",
    endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
    tokenStorage,
  });
}

describe("OAuth2Provider error state", () => {
  it("surfaces a rejected session probe as an OAuth2Error", async () => {
    await act(async () => {
      render(
        <OAuth2Provider client={new ProbeRejectingClient()}>
          <ErrorCodeProbe />
        </OAuth2Provider>,
      );
    });

    assertStrictEquals(screen.getByTestId("code").textContent, "server_error");
  });

  it("surfaces an undecodable id_token as an OAuth2Error", async () => {
    const idToken = `header.${
      base64urlEncode(new TextEncoder().encode("not json"))
    }.sig`;
    const client = directClientWithIdToken(idToken);

    await act(async () => {
      render(
        <OAuth2Provider client={client} initialState={{ isLoading: false }}>
          <ErrorCodeProbe />
        </OAuth2Provider>,
      );
    });

    await act(async () => {
      await client.getSession();
    });

    assertStrictEquals(screen.getByTestId("code").textContent, "server_error");
  });
});

describe("OAuth2Callback error state", () => {
  it("surfaces a callback URL with no code as an OAuth2Error", async () => {
    const client = new DirectClient({
      clientId: "spa",
      endpoints: { authorization: AUTHORIZE_URL, token: TOKEN_URL },
    });
    const originalHref = window.location.href;
    window.history.replaceState(null, "", "/callback?state=whatever");

    try {
      await act(async () => {
        render(
          <OAuth2Provider client={client} initialState={{ isLoading: false }}>
            <OAuth2Callback
              fallback={(error) => (
                <span data-testid="code">{error.extensions.error}</span>
              )}
            />
          </OAuth2Provider>,
        );
      });

      assertStrictEquals(
        screen.getByTestId("code").textContent,
        "server_error",
      );
    } finally {
      window.history.replaceState(null, "", originalHref);
    }
  });

  it("surfaces the wrong-client refusal as an OAuth2Error", async () => {
    await act(async () => {
      render(
        <OAuth2Provider
          client={new ProbeRejectingClient()}
          initialState={{ isLoading: false }}
        >
          <OAuth2Callback
            fallback={(error) => (
              <span data-testid="code">{error.extensions.error}</span>
            )}
          />
        </OAuth2Provider>,
      );
    });

    assertStrictEquals(screen.getByTestId("code").textContent, "server_error");
  });
});
