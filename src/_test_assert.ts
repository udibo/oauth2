import { assert, expect } from "vitest";

type ErrorConstructor<E extends Error> = abstract new (...args: never[]) => E;

function inspect<E extends Error>(
  error: unknown,
  ErrorClass: ErrorConstructor<E> | undefined,
  messageIncludes: string | RegExp | undefined,
  failureMessage: string | undefined,
): E {
  if (ErrorClass) expect(error, failureMessage).toBeInstanceOf(ErrorClass);
  if (messageIncludes !== undefined) {
    assert(error instanceof Error, "expected an Error to inspect its message");
    if (typeof messageIncludes === "string") {
      expect(error.message).toContain(messageIncludes);
    } else {
      expect(error.message).toMatch(messageIncludes);
    }
  }
  return error as E;
}

/**
 * Runs `action`, fails unless it throws, and returns what it threw. With an
 * `ErrorClass` the thrown value must be an instance of it; with
 * `messageIncludes` its message must contain the text.
 */
export function thrown<E extends Error = Error>(
  action: () => unknown,
  ErrorClass?: ErrorConstructor<E>,
  messageIncludes?: string | RegExp,
  failureMessage?: string,
): E {
  try {
    action();
  } catch (error) {
    return inspect(error, ErrorClass, messageIncludes, failureMessage);
  }
  return expect.unreachable(failureMessage ?? "expected the action to throw");
}

/**
 * Awaits `action` (a promise, or a function returning one), fails unless it
 * rejects, and returns the rejection. Checks the same as {@link thrown}.
 */
export async function rejection<E extends Error = Error>(
  action: Promise<unknown> | (() => unknown),
  ErrorClass?: ErrorConstructor<E>,
  messageIncludes?: string | RegExp,
  failureMessage?: string,
): Promise<E> {
  try {
    await (typeof action === "function" ? action() : action);
  } catch (error) {
    return inspect(error, ErrorClass, messageIncludes, failureMessage);
  }
  return expect.unreachable(failureMessage ?? "expected the action to reject");
}
