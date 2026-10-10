import { assert, describe, expect, it, vi } from "vitest";
import { FakeTime } from "../_test_fake-time.ts";
import { render, screen } from "@testing-library/react";
import { act, type ReactNode, StrictMode } from "react";

import { DirectClient } from "../client/direct-client.ts";
import { OAuth2Callback } from "./callback.tsx";
import { OAuth2Provider } from "./provider.tsx";
import { RequireAuth } from "./require-auth.tsx";
import { useAuthorization } from "./use-authorization.ts";
import { useBffClient, useDirectClient, useOAuth2 } from "./use-oauth2.ts";
import {
  createMockBffClient,
  createMockDirectClient,
  createMockOAuth2Client,
  MockOAuth2Provider,
} from "./testing.tsx";

function Probe(): ReactNode {
  const { isAuthenticated, isLoading, user } = useOAuth2();
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="auth">{String(isAuthenticated)}</span>
      <span data-testid="user">{user ? String(user.sub) : "none"}</span>
    </div>
  );
}

function AuthorizationProbe(): ReactNode {
  const authorization = useAuthorization();
  return (
    <div>
      <span data-testid="can">{String(authorization.can("posts:write"))}</span>
      <span data-testid="org">
        {String(authorization.inOrganization("acme"))}
      </span>
      <span data-testid="role">{String(authorization.hasRole("editor"))}</span>
    </div>
  );
}

describe("useAuthorization", () => {
  it("derives the checks from the session's claims", () => {
    const client = createMockOAuth2Client({
      isAuthenticated: true,
      user: {
        sub: "u1",
        roles: ["editor"],
        permissions: ["posts:write"],
        org_id: "org-1",
        org_slug: "acme",
        org_roles: ["admin"],
      },
    });
    render(
      <MockOAuth2Provider client={client}>
        <AuthorizationProbe />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("can").textContent).toBe("true");
    expect(screen.getByTestId("org").textContent).toBe("true");
    expect(screen.getByTestId("role").textContent).toBe("true");
  });

  it("answers everything false for an anonymous session", () => {
    const client = createMockOAuth2Client({ isAuthenticated: false });
    render(
      <MockOAuth2Provider client={client}>
        <AuthorizationProbe />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("can").textContent).toBe("false");
    expect(screen.getByTestId("org").textContent).toBe("false");
    expect(screen.getByTestId("role").textContent).toBe("false");
  });
});

describe("MockOAuth2Provider + useOAuth2", () => {
  it("derives its initial state from the client when no state is passed", () => {
    const client = createMockOAuth2Client({
      isAuthenticated: true,
      user: { sub: "u1" },
    });
    render(
      <MockOAuth2Provider client={client}>
        <Probe />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("user").textContent).toBe("u1");
  });

  it("lets an explicit state override the client, user: null included", () => {
    const client = createMockOAuth2Client({
      isAuthenticated: true,
      user: { sub: "u1" },
    });
    render(
      <MockOAuth2Provider
        client={client}
        state={{ isAuthenticated: false, user: null }}
      >
        <Probe />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("false");
    expect(
      screen.getByTestId("user").textContent,
      "an explicit null must override the client's user, not fall back to it",
    ).toBe("none");
  });

  it("reports signed out for a client built unauthenticated", () => {
    const client = createMockOAuth2Client();
    render(
      <MockOAuth2Provider client={client}>
        <Probe />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("false");
    expect(screen.getByTestId("user").textContent).toBe("none");
  });

  it("initialState is a construction snapshot, not live client state", () => {
    const client = createMockOAuth2Client();
    client.signIn({ sub: "later" });
    expect(client.initialState).toStrictEqual({
      isAuthenticated: false,
      user: null,
    });
  });

  it("keeps the construction snapshot when the client signs out later", () => {
    const client = createMockOAuth2Client({ user: { sub: "u1" } });
    render(
      <MockOAuth2Provider client={client}>
        <Probe />
      </MockOAuth2Provider>,
    );
    act(() => client.signOut());
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("user").textContent).toBe("u1");
  });

  it("re-renders when client.signIn / signOut emit events", async () => {
    const client = createMockOAuth2Client();
    function Wrapper(): ReactNode {
      const { isAuthenticated, login } = useOAuth2();
      return (
        <div>
          <span data-testid="auth">{String(isAuthenticated)}</span>
          <button type="button" onClick={() => login()}>
            login
          </button>
        </div>
      );
    }
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <Wrapper />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("false");
    await act(async () => {
      client.signIn({ sub: "u2" });
    });
    expect(screen.getByTestId("auth").textContent).toBe("true");
    act(() => client.signOut());
    expect(screen.getByTestId("auth").textContent).toBe("false");
  });

  it("populates user after an authenticated event", async () => {
    const client = createMockOAuth2Client();
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("user").textContent).toBe("none");
    await act(async () => {
      client.signIn({ sub: "u-pub" });
    });
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("user").textContent).toBe("u-pub");
  });

  it("OAuth2Provider probes getSession and exposes logoutUrl", async () => {
    const client = createMockOAuth2Client({
      isAuthenticated: true,
      user: { sub: "u-bff" },
    });
    function Show(): ReactNode {
      const { isAuthenticated, logoutUrl } = useOAuth2();
      return (
        <div>
          <span data-testid="auth">{String(isAuthenticated)}</span>
          <span data-testid="logout">{logoutUrl ?? "none"}</span>
        </div>
      );
    }
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Show />
        </OAuth2Provider>,
      );
    });
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("logout").textContent).toBe("/auth/logout");
  });

  it("throws a clear error when used outside any provider", () => {
    function ConsumerOutsideProvider(): ReactNode {
      useOAuth2();
      return null;
    }
    let caught: unknown;
    try {
      render(<ConsumerOutsideProvider />);
    } catch (err) {
      caught = err;
    }
    expect(caught instanceof Error).toStrictEqual(true);
    expect((caught as Error).message.includes("OAuth2Provider")).toStrictEqual(
      true,
    );
  });

  it("useDirectClient rejects a client that is not a DirectClient", () => {
    const client = createMockOAuth2Client();
    function Caller(): ReactNode {
      let err: string | undefined;
      try {
        useDirectClient();
      } catch (e) {
        err = (e as Error).message;
      }
      return <span data-testid="err">{err ?? "no error"}</span>;
    }
    render(
      <MockOAuth2Provider client={client}>
        <Caller />
      </MockOAuth2Provider>,
    );
    expect(
      screen.getByTestId("err").textContent?.includes("DirectClient"),
    ).toStrictEqual(true);
  });

  it("useBffClient returns the provider's BffClient", () => {
    const client = createMockBffClient();
    let resolved: unknown;
    function Caller(): ReactNode {
      resolved = useBffClient();
      return null;
    }
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <Caller />
      </OAuth2Provider>,
    );
    expect(resolved === client).toStrictEqual(true);
  });

  it("useBffClient rejects a client that is not a BffClient", () => {
    const client = createMockOAuth2Client();
    function Caller(): ReactNode {
      let err: string | undefined;
      try {
        useBffClient();
      } catch (e) {
        err = (e as Error).message;
      }
      return <span data-testid="err">{err ?? "no error"}</span>;
    }
    render(
      <MockOAuth2Provider client={client}>
        <Caller />
      </MockOAuth2Provider>,
    );
    expect(
      screen.getByTestId("err").textContent?.includes("BffClient"),
    ).toStrictEqual(true);
  });
});

describe("narrowing hooks", () => {
  it("useDirectClient returns the provider's DirectClient", () => {
    const client = createMockDirectClient();
    let resolved: unknown;
    function Caller(): ReactNode {
      resolved = useDirectClient();
      return null;
    }
    render(
      <MockOAuth2Provider client={client}>
        <Caller />
      </MockOAuth2Provider>,
    );
    assert(resolved === client, "the hook must hand back the same instance");
  });

  it("exposes getAccessToken through the narrowed DirectClient", async () => {
    const client = createMockDirectClient({ user: { sub: "u1" } });
    let token: string | undefined;
    function Caller(): ReactNode {
      const direct = useDirectClient();
      void direct.getAccessToken().then((value) => {
        token = value;
      });
      return null;
    }
    await act(async () => {
      render(
        <MockOAuth2Provider client={client}>
          <Caller />
        </MockOAuth2Provider>,
      );
    });
    expect(token).toBe("mock-access-token");
  });

  it("exposes loginContinuation through the narrowed BffClient", () => {
    const client = createMockBffClient();
    function Caller(): ReactNode {
      return (
        <span data-testid="href">{useBffClient().loginContinuation("/x")}</span>
      );
    }
    render(
      <MockOAuth2Provider client={client}>
        <Caller />
      </MockOAuth2Provider>,
    );
    expect(screen.getByTestId("href").textContent).toBe(
      "/auth/login?return_to=%2Fx",
    );
  });
});

describe("OAuth2Callback", () => {
  it("renders its fallback when the provider holds the wrong client", async () => {
    const client = createMockBffClient();
    await act(async () => {
      render(
        <MockOAuth2Provider client={client}>
          <OAuth2Callback
            fallback={(error) => <span data-testid="err">{error.message}</span>}
          />
        </MockOAuth2Provider>,
      );
    });
    expect(
      screen.getByTestId("err").textContent?.includes("DirectClient"),
      "the wrong-client error must reach `fallback`, not escape as a throw",
    ).toStrictEqual(true);
  });
});

describe("OAuth2Callback defaults", () => {
  it("shows the error message in a <pre> when no fallback is given", async () => {
    await act(async () => {
      render(
        <MockOAuth2Provider client={createMockBffClient()}>
          <OAuth2Callback />
        </MockOAuth2Provider>,
      );
    });

    const message = document.querySelector("pre");
    assert(message, "the default fallback must render a <pre>");
    expect(message.textContent).toContain("DirectClient");
  });

  it("replaces the history entry with returnTo once the exchange succeeds", async () => {
    const client = new DirectClient({
      clientId: "spa",
      endpoints: {
        authorization: "http://idp.test/authorize",
        token: "http://idp.test/token",
      },
    });
    using _exchange = vi
      .spyOn(client, "handleAuthorizationCallback")
      .mockResolvedValue({ returnTo: "/dashboard" } as Awaited<
        ReturnType<DirectClient["handleAuthorizationCallback"]>
      >);
    const originalHref = window.location.href;
    try {
      await act(async () => {
        render(
          <OAuth2Provider client={client} initialState={{ isLoading: false }}>
            <OAuth2Callback />
          </OAuth2Provider>,
        );
      });

      expect(window.location.pathname).toBe("/dashboard");
    } finally {
      window.history.replaceState(null, "", originalHref);
    }
  });
});

describe("OAuth2Provider renew timer", () => {
  it("arms from the mount probe and renews before expiry", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({
      user: { sub: "u1" },
      sessionExpiresIn: 120,
    });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    expect(client.renewCount).toBe(0);

    await act(async () => {
      await time.tickAsync(91_000);
    });
    expect(client.renewCount, "the timer must fire once armed").toBe(1);
  });

  it("re-arms after a renew so the session keeps refreshing", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({
      user: { sub: "u1" },
      sessionExpiresIn: 120,
    });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });

    for (const expected of [1, 2, 3]) {
      await act(async () => {
        await time.tickAsync(91_000);
      });
      expect(client.renewCount, "each renew must schedule the next one").toBe(
        expected,
      );
    }
  });

  it("arms after an interactive login, whose event carries the expiry", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({ sessionExpiresIn: 120 });
    await act(async () => {
      render(
        <OAuth2Provider client={client} initialState={{ user: null }}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    expect(client.renewCount).toBe(0);

    await act(async () => {
      client.signIn({ sub: "u-login" });
    });
    await act(async () => {
      await time.tickAsync(91_000);
    });
    expect(
      client.renewCount,
      "the authenticated event carries accessTokenExpiresAt; the timer must use it",
    ).toBe(1);
  });

  it("re-arms off a token_refreshed event", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({ user: { sub: "u1" } });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    expect(client.renewCount, "no expiry means no timer").toBe(0);

    await act(async () => {
      client.refreshTokens(120);
    });
    await act(async () => {
      await time.tickAsync(91_000);
    });
    expect(client.renewCount).toBe(1);
  });

  it("schedules nothing while signed out", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({ sessionExpiresIn: 120 });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    await act(async () => {
      await time.tickAsync(600_000);
    });
    expect(client.renewCount).toBe(0);
  });

  it("stops renewing after logout", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({
      user: { sub: "u1" },
      sessionExpiresIn: 120,
    });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    await act(async () => {
      await time.tickAsync(91_000);
    });
    expect(client.renewCount).toBe(1);

    await act(async () => {
      client.signOut();
    });
    await act(async () => {
      await time.tickAsync(600_000);
    });
    expect(client.renewCount, "a signed-out session must not renew").toBe(1);
  });

  it("arms an immediate renew for an expired but revivable session", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({
      user: { sub: "u1" },
      sessionExpiresIn: 0,
    });
    await act(async () => {
      render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      );
    });
    expect(client.renewCount).toBe(0);

    await act(async () => {
      await time.tickAsync(6_000);
    });
    expect(
      client.renewCount,
      "sessionExpiresIn 0 means renew now, not never",
    ).toBe(1);
  });

  it("clears its timer on unmount", async () => {
    using time = new FakeTime();
    const client = createMockOAuth2Client({
      user: { sub: "u1" },
      sessionExpiresIn: 120,
    });
    let unmount = () => {};
    await act(async () => {
      unmount = render(
        <OAuth2Provider client={client}>
          <Probe />
        </OAuth2Provider>,
      ).unmount;
    });
    act(() => unmount());
    await act(async () => {
      await time.tickAsync(600_000);
    });
    expect(client.renewCount).toBe(0);
  });
});

describe("RequireAuth", () => {
  it("renders fallback while unauthenticated and children once signed in", async () => {
    const client = createMockOAuth2Client();
    using _login = vi
      .spyOn(client, "login")
      .mockImplementation(() => Promise.resolve({ url: "" }));
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <RequireAuth fallback={<span data-testid="fallback">loading</span>}>
          <span data-testid="protected">secret</span>
        </RequireAuth>
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("fallback").textContent).toBe("loading");
    await act(async () => {
      client.signIn({ sub: "u3" });
    });
    expect(screen.getByTestId("protected").textContent).toBe("secret");
  });

  it("calls login with the current path as returnTo when unauthenticated", async () => {
    const client = createMockOAuth2Client();
    using loginStub = vi
      .spyOn(client, "login")
      .mockImplementation(() => Promise.resolve({ url: "" }));
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <RequireAuth>
          <span>secret</span>
        </RequireAuth>
      </OAuth2Provider>,
    );
    await act(async () => {});
    expect(loginStub.mock.calls.length).toBeGreaterThanOrEqual(1);
    expect(
      (loginStub.mock.calls[0]?.[0] as { returnTo?: string } | undefined)
        ?.returnTo,
    ).toBe("/");
  });
});

describe("useOAuth2 navigation", () => {
  it("login() navigates the browser to the returned url", async () => {
    const client = createMockOAuth2Client();
    const assigned: string[] = [];
    const realLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: {
        origin: realLocation.origin,
        pathname: "/",
        search: "",
        assign: (url: string) => assigned.push(url),
      },
    });
    try {
      let doLogin: () => void = () => {};
      const Caller = (): ReactNode => {
        const { login } = useOAuth2();
        doLogin = () => void login();
        return null;
      };
      render(
        <OAuth2Provider client={client} initialState={{ user: null }}>
          <Caller />
        </OAuth2Provider>,
      );
      await act(async () => {
        doLogin();
      });
      expect(assigned).toStrictEqual(["mock://login"]);
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: realLocation,
      });
    }
  });

  it("logout() navigates the browser to the returned url", async () => {
    const client = createMockOAuth2Client();
    using _logout = vi
      .spyOn(client, "logout")
      .mockResolvedValue({ url: "https://idp.test/end-session" });
    const assigned: string[] = [];
    const realLocation = window.location;
    Object.defineProperty(window, "location", {
      configurable: true,
      value: {
        origin: realLocation.origin,
        pathname: "/",
        search: "",
        assign: (url: string) => assigned.push(url),
      },
    });
    try {
      let doLogout: () => void = () => {};
      const Caller = (): ReactNode => {
        const { logout } = useOAuth2();
        doLogout = () => void logout();
        return null;
      };
      render(
        <OAuth2Provider client={client} initialState={{ user: null }}>
          <Caller />
        </OAuth2Provider>,
      );
      await act(async () => {
        doLogout();
      });
      expect(assigned).toStrictEqual(["https://idp.test/end-session"]);
    } finally {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: realLocation,
      });
    }
  });
});

describe("OAuth2Provider initialState", () => {
  it("avoids the on-mount probe when initialState is supplied", () => {
    const client = createMockOAuth2Client();
    let probeCalls = 0;
    const originalGetUser = client.getUser;
    client.getUser = () => {
      probeCalls++;
      return originalGetUser.call(client);
    };
    render(
      <OAuth2Provider
        client={client}
        initialState={{ user: { sub: "ssr-user" }, isAuthenticated: true }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("user").textContent).toBe("ssr-user");
    expect(probeCalls).toBe(0);
  });

  it("survives StrictMode double-mount without re-running the probe", () => {
    const client = createMockOAuth2Client();
    let probeCalls = 0;
    const originalGetUser = client.getUser;
    client.getUser = () => {
      probeCalls++;
      return originalGetUser.call(client);
    };
    render(
      <StrictMode>
        <OAuth2Provider
          client={client}
          initialState={{ user: { sub: "u4" }, isAuthenticated: true }}
        >
          <Probe />
        </OAuth2Provider>
      </StrictMode>,
    );
    expect(probeCalls).toBe(0);
  });

  it("re-syncs when a later SSR navigation supplies updated initialState (BFF login)", () => {
    // Regression: the provider must reflect a fresh initialState without a
    // remount; it previously read initialState only in the useState initializer.
    const client = createMockOAuth2Client();
    const { rerender } = render(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: false, user: null }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("false");

    rerender(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: true, user: { sub: "ssr-u" } }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("true");
    expect(screen.getByTestId("user").textContent).toBe("ssr-u");
  });

  it("re-syncs to signed-out when initialState flips to unauthenticated", () => {
    const client = createMockOAuth2Client();
    const { rerender } = render(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: true, user: { sub: "ssr-u" } }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("true");

    rerender(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: false, user: null }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    expect(screen.getByTestId("auth").textContent).toBe("false");
    expect(screen.getByTestId("user").textContent).toBe("none");
  });
});
