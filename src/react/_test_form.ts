import { assert } from "vitest";

/** The rendered `<form>`, failing the test when the component rendered none. */
export function getForm(container: HTMLElement): HTMLFormElement {
  const form = container.querySelector("form");
  assert(form, "expected a <form>");
  return form;
}
