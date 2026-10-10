import { render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { RouterContextProvider } from "react-router";
import { describe, expect, it } from "vitest";

import { requestContext } from "./context.ts";
import { useMockServer } from "../test/server.ts";
import { renderUnderRoot, signedIn, stubProps } from "../test/render.tsx";

useMockServer();
import { ErrorBoundary, headers, loader } from "./root.tsx";

describe("root route", () => {
  it("hands the server's request context to every page as loader data", () => {
    const context = new RouterContextProvider();
    const value = { session: signedIn(), demoAccount: false };
    context.set(requestContext, value);

    expect(loader(stubProps<Parameters<typeof loader>[0]>({ context }))).toBe(
      value,
    );
  });

  it("forbids shared caches from storing a page that carries the session", () => {
    expect(headers().get("Cache-Control")).toBe("private, no-store");
  });

  it("renders a signed-in page on the first paint without probing the session", async () => {
    await renderUnderRoot([{ index: true, Component: () => <p>inside</p> }], {
      entry: "/",
      session: signedIn(),
    });

    expect(screen.getByText("inside")).toBeInTheDocument();
  });

  it("reports a route error response by status", () => {
    render(
      <ErrorBoundary
        {...stubProps<ComponentProps<typeof ErrorBoundary>>({
          error: {
            status: 404,
            statusText: "Not Found",
            internal: false,
            data: null,
          },
        })}
      />,
    );

    expect(screen.getByRole("heading")).toHaveTextContent("404 Not Found");
  });

  it("reports an unexpected error generically", () => {
    render(
      <ErrorBoundary
        {...stubProps<ComponentProps<typeof ErrorBoundary>>({
          error: new Error("boom"),
        })}
      />,
    );

    expect(screen.getByRole("heading")).toHaveTextContent(
      "Something went wrong",
    );
    expect(screen.queryByText("boom")).toBeNull();
  });
});
