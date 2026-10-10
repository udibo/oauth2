import { type ReactNode, useState } from "react";
import {
  isRouteErrorResponse,
  Links,
  Meta,
  Outlet,
  Scripts,
  ScrollRestoration,
} from "react-router";

import { OAuth2Provider } from "@udibo/oauth2/react";

import { requestContext } from "./context.ts";
import { createBrowserClient } from "./oauth2/browser-client.ts";
import type { Route } from "./+types/root";

import "./app.css";

export function loader({ context }: Route.LoaderArgs) {
  return context.get(requestContext);
}

export function links(): Route.LinkDescriptors {
  return [{ rel: "icon", href: "data:," }];
}

/** The loader carries the signed-in session, so no shared cache may store the page. */
export function headers(): Headers {
  return new Headers({ "Cache-Control": "private, no-store" });
}

export function Layout({ children }: { children: ReactNode }): ReactNode {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <Meta />
        <Links />
      </head>
      <body className="min-h-dvh font-sans">
        {children}
        <ScrollRestoration />
        <Scripts />
      </body>
    </html>
  );
}

export default function App({ loaderData }: Route.ComponentProps): ReactNode {
  const [client] = useState(createBrowserClient);
  return (
    <OAuth2Provider client={client} initialState={loaderData.session}>
      <Outlet />
    </OAuth2Provider>
  );
}

export function ErrorBoundary({ error }: Route.ErrorBoundaryProps): ReactNode {
  const message = isRouteErrorResponse(error)
    ? `${error.status} ${error.statusText}`
    : "Something went wrong";
  return (
    <main className="mx-auto max-w-2xl p-8">
      <h1>{message}</h1>
    </main>
  );
}
