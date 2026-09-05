import { cleanupAfterEach } from "../_test_setup.ts";

import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { act, renderHook } from "@testing-library/react";

import { useAuthForm } from "./use-auth-form.ts";

cleanupAfterEach();

describe("useAuthForm", () => {
  it("submits the current values to onSubmit", async () => {
    const submitted: Array<{ email: string }> = [];
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: (values) => {
          submitted.push({ ...values });
        },
      })
    );

    act(() => result.current.setValue("email", "a@b.com"));
    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(submitted, [{ email: "a@b.com" }]);
    assertEquals(result.current.succeeded, true);
    assertEquals(result.current.status, "success");
  });

  it("runs onSubmit once for a same-tick double submit", async () => {
    let calls = 0;
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "a@b.com" },
        onSubmit: async () => {
          calls++;
          await Promise.resolve();
        },
      })
    );

    await act(async () => {
      await Promise.all([
        result.current.handleSubmit(),
        result.current.handleSubmit(),
      ]);
    });

    assertEquals(calls, 1, "the re-entrancy lock blocks the second submit");
  });

  it("swallows an onSuccess that throws, keeping the success state", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "a@b.com" },
        onSubmit: () => {},
        onSuccess: () => {
          throw new Error("navigate blew up");
        },
      })
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(result.current.status, "success");
  });

  it("populates field and form errors from the result", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => ({
          error: "Nope",
          fieldErrors: { email: "Bad email" },
        }),
      })
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(result.current.formError, "Nope");
    assertEquals(result.current.errors.email, "Bad email");
    assertEquals(result.current.status, "error");
  });

  it("blocks submission when validate returns errors", async () => {
    let called = false;
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { password: "", confirmPassword: "" },
        validate: (values) =>
          values.password !== values.confirmPassword
            ? { confirmPassword: "Mismatch" }
            : {},
        onSubmit: () => {
          called = true;
        },
      })
    );

    act(() => result.current.setValue("password", "x"));
    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(called, false);
    assertEquals(result.current.errors.confirmPassword, "Mismatch");
  });

  it("captures a thrown error as the form error", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => {
          throw new Error("boom");
        },
      })
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(result.current.formError, "boom");
  });

  it("traps a throwing validate as a form error without calling onSubmit", async () => {
    let called = false;
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        validate: () => {
          throw new Error("validator blew up");
        },
        onSubmit: () => {
          called = true;
        },
      })
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    assertEquals(called, false);
    assertEquals(result.current.formError, "validator blew up");
    assertEquals(result.current.status, "error");
  });

  it("tracks submitting state and submitCount", async () => {
    let resolve: (() => void) | undefined;
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () =>
          new Promise<void>((r) => {
            resolve = r;
          }),
      })
    );

    let pending: Promise<void>;
    act(() => {
      pending = result.current.handleSubmit();
    });
    assertEquals(result.current.isSubmitting, true);
    assertEquals(result.current.submitCount, 1);

    await act(async () => {
      resolve?.();
      await pending;
    });
    assertEquals(result.current.isSubmitting, false);
  });

  it("ignores a second submit while one is in flight", async () => {
    let calls = 0;
    let resolve: (() => void) | undefined;
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => {
          calls++;
          return new Promise<void>((r) => {
            resolve = r;
          });
        },
      })
    );

    let pending: Promise<void>;
    act(() => {
      pending = result.current.handleSubmit();
    });
    assertEquals(result.current.isSubmitting, true);

    await act(async () => {
      await result.current.handleSubmit();
    });
    assertEquals(calls, 1);
    assertEquals(result.current.submitCount, 1);

    await act(async () => {
      resolve?.();
      await pending;
    });
    assertEquals(calls, 1);
  });

  it("wires aria attributes through getFieldProps only when errored", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => ({ fieldErrors: { email: "Required" } }),
      })
    );

    assertEquals(
      result.current.getFieldProps("email")["aria-invalid"],
      undefined,
    );
    await act(async () => {
      await result.current.handleSubmit();
    });
    const props = result.current.getFieldProps("email");
    assertEquals(props["aria-invalid"], true);
    assertEquals(props["aria-describedby"], `${props.id}-error`);
  });
});
