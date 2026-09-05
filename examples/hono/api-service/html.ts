/**
 * Tiny HTML helpers shared by the inline-template routes.
 *
 * A real app would use a template engine (Hono has `hono/html` for
 * tagged-template strings with auto-escaping); this example sticks to
 * raw template strings so readers don't have to learn a template
 * library to follow the wiring.
 *
 * @module
 */

/** Escapes the five XML special characters for safe HTML interpolation. */
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
