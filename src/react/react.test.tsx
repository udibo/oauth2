// deno-lint-ignore-file no-window require-await -- jsdom provides `window`; `act(async …)` needs the async signature
import { cleanupAfterEach } from "./_test_setup.ts";

import { assert, assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { stub } from "@std/testing/mock";
import { FakeTime } from "@std/testing/time";
import { render, screen } from "@testing-library/react";
import { act, type ReactNode, StrictMode } from "react";

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

cleanupAfterEach();

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
    assertStrictEquals(screen.getByTestId("can").textContent, "true");
    assertStrictEquals(screen.getByTestId("org").textContent, "true");
    assertStrictEquals(screen.getByTestId("role").textContent, "true");
  });

  it("answers everything false for an anonymous session", () => {
    const client = createMockOAuth2Client({ isAuthenticated: false });
    render(
      <MockOAuth2Provider client={client}>
        <AuthorizationProbe />
      </MockOAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("can").textContent, "false");
    assertStrictEquals(screen.getByTestId("org").textContent, "false");
    assertStrictEquals(screen.getByTestId("role").textContent, "false");
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(screen.getByTestId("user").textContent, "u1");
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");
    assertStrictEquals(
      screen.getByTestId("user").textContent,
      "none",
      "an explicit null must override the client's user, not fall back to it",
    );
  });

  it("reports signed out for a client built unauthenticated", () => {
    const client = createMockOAuth2Client();
    render(
      <MockOAuth2Provider client={client}>
        <Probe />
      </MockOAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");
    assertStrictEquals(screen.getByTestId("user").textContent, "none");
  });

  it("initialState is a construction snapshot, not live client state", () => {
    const client = createMockOAuth2Client();
    client.signIn({ sub: "later" });
    assertEquals(client.initialState, { isAuthenticated: false, user: null });
  });

  it("keeps the construction snapshot when the client signs out later", () => {
    const client = createMockOAuth2Client({ user: { sub: "u1" } });
    render(
      <MockOAuth2Provider client={client}>
        <Probe />
      </MockOAuth2Provider>,
    );
    act(() => client.signOut());
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(screen.getByTestId("user").textContent, "u1");
  });

  it("re-renders when client.signIn / signOut emit events", async () => {
    const client = createMockOAuth2Client();
    function Wrapper(): ReactNode {
      const { isAuthenticated, login } = useOAuth2();
      return (
        <div>
          <span data-testid="auth">{String(isAuthenticated)}</span>
          <button type="button" onClick={() => login()}>login</button>
        </div>
      );
    }
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <Wrapper />
      </OAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");
    await act(async () => {
      client.signIn({ sub: "u2" });
    });
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    act(() => client.signOut());
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");
  });

  it("populates user after an authenticated event", async () => {
    const client = createMockOAuth2Client();
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <Probe />
      </OAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("user").textContent, "none");
    await act(async () => {
      client.signIn({ sub: "u-pub" });
    });
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(screen.getByTestId("user").textContent, "u-pub");
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(
      screen.getByTestId("logout").textContent,
      "/auth/logout",
    );
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
    assertEquals(caught instanceof Error, true);
    assertEquals(
      (caught as Error).message.includes("OAuth2Provider"),
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
    assertEquals(
      screen.getByTestId("err").textContent?.includes("DirectClient"),
      true,
    );
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
    assertEquals(resolved === client, true);
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
    assertEquals(
      screen.getByTestId("err").textContent?.includes("BffClient"),
      true,
    );
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
      direct.getAccessToken().then((value) => {
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
    assertStrictEquals(token, "mock-access-token");
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
    assertStrictEquals(
      screen.getByTestId("href").textContent,
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
    assertEquals(
      screen.getByTestId("err").textContent?.includes("DirectClient"),
      true,
      "the wrong-client error must reach `fallback`, not escape as a throw",
    );
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
    assertStrictEquals(client.renewCount, 0);

    await act(async () => {
      await time.tickAsync(91_000);
    });
    assertStrictEquals(client.renewCount, 1, "the timer must fire once armed");
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
      assertStrictEquals(
        client.renewCount,
        expected,
        "each renew must schedule the next one",
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
    assertStrictEquals(client.renewCount, 0);

    await act(async () => {
      client.signIn({ sub: "u-login" });
    });
    await act(async () => {
      await time.tickAsync(91_000);
    });
    assertStrictEquals(
      client.renewCount,
      1,
      "the authenticated event carries accessTokenExpiresAt; the timer must use it",
    );
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
    assertStrictEquals(client.renewCount, 0, "no expiry means no timer");

    await act(async () => {
      client.refreshTokens(120);
    });
    await act(async () => {
      await time.tickAsync(91_000);
    });
    assertStrictEquals(client.renewCount, 1);
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
    assertStrictEquals(client.renewCount, 0);
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
    assertStrictEquals(client.renewCount, 1);

    await act(async () => {
      client.signOut();
    });
    await act(async () => {
      await time.tickAsync(600_000);
    });
    assertStrictEquals(
      client.renewCount,
      1,
      "a signed-out session must not renew",
    );
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
    assertStrictEquals(client.renewCount, 0);

    await act(async () => {
      await time.tickAsync(6_000);
    });
    assertStrictEquals(
      client.renewCount,
      1,
      "sessionExpiresIn 0 means renew now, not never",
    );
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
    assertStrictEquals(client.renewCount, 0);
  });
});

describe("RequireAuth", () => {
  it("renders fallback while unauthenticated and children once signed in", async () => {
    const client = createMockOAuth2Client();
    using _login = stub(
      client,
      "login",
      () => Promise.resolve({ url: "" }),
    );
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <RequireAuth fallback={<span data-testid="fallback">loading</span>}>
          <span data-testid="protected">secret</span>
        </RequireAuth>
      </OAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("fallback").textContent, "loading");
    await act(async () => {
      client.signIn({ sub: "u3" });
    });
    assertStrictEquals(screen.getByTestId("protected").textContent, "secret");
  });

  it("calls login with the current path as returnTo when unauthenticated", async () => {
    const client = createMockOAuth2Client();
    using loginStub = stub(
      client,
      "login",
      () => Promise.resolve({ url: "" }),
    );
    render(
      <OAuth2Provider client={client} initialState={{ user: null }}>
        <RequireAuth>
          <span>secret</span>
        </RequireAuth>
      </OAuth2Provider>,
    );
    await act(async () => {});
    assertEquals(loginStub.calls.length >= 1, true);
    assertStrictEquals(
      (loginStub.calls[0].args[0] as { returnTo?: string } | undefined)
        ?.returnTo,
      "/",
    );
  });
});

describe("useOAuth2 navigation", () => {
  it("login() navigates the browser to the returned url", async () => {
    const client = createMockOAuth2Client();
    const assigned: string[] = [];
    const realLocation = window.location;
    let replaced = false;
    try {
      Object.defineProperty(window, "location", {
        configurable: true,
        value: {
          origin: realLocation.origin,
          pathname: "/",
          search: "",
          assign: (url: string) => assigned.push(url),
        },
      });
      replaced = true;
    } catch {
      // Some runtimes pin `window.location`; skip the assertion there.
    }
    if (!replaced) return;
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
      assertEquals(assigned, ["mock://login"]);
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(screen.getByTestId("user").textContent, "ssr-user");
    assertStrictEquals(probeCalls, 0);
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
    assertStrictEquals(probeCalls, 0);
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");

    rerender(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: true, user: { sub: "ssr-u" } }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");
    assertStrictEquals(screen.getByTestId("user").textContent, "ssr-u");
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
    assertStrictEquals(screen.getByTestId("auth").textContent, "true");

    rerender(
      <OAuth2Provider
        client={client}
        initialState={{ isAuthenticated: false, user: null }}
      >
        <Probe />
      </OAuth2Provider>,
    );
    assertStrictEquals(screen.getByTestId("auth").textContent, "false");
    assertStrictEquals(screen.getByTestId("user").textContent, "none");
  });
});
