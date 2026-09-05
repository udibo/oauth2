/**
 * Shared harness for the React adapter's component tests. Importing this module
 * installs the global DOM (jsdom) and marks React's `act()` environment, so it
 * must be the **first** import in a test file — before `@testing-library/react`.
 *
 * @module
 */

import "@udibo/juniper/utils/global-jsdom";

import { assert } from "@std/assert";
import { afterEach } from "@std/testing/bdd";
import { cleanup } from "@testing-library/react";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

/** Unmounts anything rendered by the test after each case. Call once per file. */
export function cleanupAfterEach(): void {
  afterEach(() => cleanup());
}

/** The rendered `<form>`, failing the test when the component rendered none. */
export function getForm(container: HTMLElement): HTMLFormElement {
  const form = container.querySelector("form");
  assert(form, "expected a <form>");
  return form;
}
