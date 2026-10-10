import { render, type RenderResult, waitFor } from "@testing-library/react";
import type { ComponentProps } from "react";
import { createRoutesStub } from "react-router";
import { expect, vi } from "vitest";

import type { SessionState } from "@udibo/oauth2/client";

import type { RequestContext } from "../app/context.ts";
import RootApp from "../app/root.tsx";

type StubRoutes = Parameters<typeof createRoutesStub>[0];

export const signedOut: SessionState = {
  isAuthenticated: false,
  user: null,
  sessionExpiresIn: null,
  logoutUrl: null,
};

export function signedIn(
  user: Record<string, unknown> = {
    sub: "user-1",
    name: "Ada Lovelace",
    email: "ada@example.com",
  },
): SessionState {
  return {
    isAuthenticated: true,
    user: user as SessionState["user"],
    sessionExpiresIn: 900,
    logoutUrl: "/auth/logout",
  };
}

/**
 * Renders `routes` under the real root route, so every page sees the same
 * `<OAuth2Provider>` seeded from the same loader data the server provides.
 * Resolves once the route loaders have run and the page is on screen.
 */
export async function renderUnderRoot(
  routes: StubRoutes,
  options: {
    entry: string;
    session?: SessionState;
    demoAccount?: boolean;
  },
): Promise<RenderResult> {
  const requestContext: RequestContext = {
    session: options.session ?? signedOut,
    demoAccount: options.demoAccount ?? true,
  };
  const Stub = createRoutesStub([
    {
      id: "root",
      path: "/",
      Component: () => (
        <RootApp
          {...stubProps<ComponentProps<typeof RootApp>>({
            loaderData: requestContext,
          })}
        />
      ),
      loader: () => requestContext,
      children: routes,
    },
  ]);
  const result = render(<Stub initialEntries={[options.entry]} />);
  await waitFor(() => expect(result.container).not.toBeEmptyDOMElement());
  return result;
}

/** Replaces `window.location` so `assign` records where the app navigated. */
export function captureNavigation(): string[] {
  const assigned: string[] = [];
  vi.stubGlobal("location", {
    href: window.location.href,
    origin: window.location.origin,
    pathname: window.location.pathname,
    search: window.location.search,
    assign: (to: string) => assigned.push(to),
  });
  return assigned;
}

/** Builds the slice of a route's generated props that a test cares about. */
export function stubProps<T>(props: object): T {
  return props as unknown as T;
}
