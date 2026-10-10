import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";

import { useAuthForm } from "./use-auth-form.ts";

describe("useAuthForm", () => {
  it("submits the current values to onSubmit", async () => {
    const submitted: Array<{ email: string }> = [];
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: (values) => {
          submitted.push({ ...values });
        },
      }),
    );

    act(() => result.current.setValue("email", "a@b.com"));
    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(submitted).toStrictEqual([{ email: "a@b.com" }]);
    expect(result.current.succeeded).toStrictEqual(true);
    expect(result.current.status).toStrictEqual("success");
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
      }),
    );

    await act(async () => {
      await Promise.all([
        result.current.handleSubmit(),
        result.current.handleSubmit(),
      ]);
    });

    expect(
      calls,
      "the re-entrancy lock blocks the second submit",
    ).toStrictEqual(1);
  });

  it("swallows an onSuccess that throws, keeping the success state", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "a@b.com" },
        onSubmit: () => {},
        onSuccess: () => {
          throw new Error("navigate blew up");
        },
      }),
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(result.current.status).toStrictEqual("success");
  });

  it("populates field and form errors from the result", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => ({
          error: "Nope",
          fieldErrors: { email: "Bad email" },
        }),
      }),
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(result.current.formError).toStrictEqual("Nope");
    expect(result.current.errors.email).toStrictEqual("Bad email");
    expect(result.current.status).toStrictEqual("error");
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
      }),
    );

    act(() => result.current.setValue("password", "x"));
    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(called).toStrictEqual(false);
    expect(result.current.errors.confirmPassword).toStrictEqual("Mismatch");
  });

  it("captures a thrown error as the form error", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => {
          throw new Error("boom");
        },
      }),
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(result.current.formError).toStrictEqual("boom");
    expect(result.current.isSubmitting).toStrictEqual(false);
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
      }),
    );

    await act(async () => {
      await result.current.handleSubmit();
    });

    expect(called).toStrictEqual(false);
    expect(result.current.formError).toStrictEqual("validator blew up");
    expect(result.current.status).toStrictEqual("error");
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
      }),
    );

    let pending: Promise<void>;
    act(() => {
      pending = result.current.handleSubmit();
    });
    expect(result.current.isSubmitting).toStrictEqual(true);
    expect(result.current.submitCount).toStrictEqual(1);

    await act(async () => {
      resolve?.();
      await pending;
    });
    expect(result.current.isSubmitting).toStrictEqual(false);
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
      }),
    );

    let pending: Promise<void>;
    act(() => {
      pending = result.current.handleSubmit();
    });
    expect(result.current.isSubmitting).toStrictEqual(true);

    await act(async () => {
      await result.current.handleSubmit();
    });
    expect(calls).toStrictEqual(1);
    expect(result.current.submitCount).toStrictEqual(1);

    await act(async () => {
      resolve?.();
      await pending;
    });
    expect(calls).toStrictEqual(1);
  });

  it("wires aria attributes through getFieldProps only when errored", async () => {
    const { result } = renderHook(() =>
      useAuthForm({
        initialValues: { email: "" },
        onSubmit: () => ({ fieldErrors: { email: "Required" } }),
      }),
    );

    expect(result.current.getFieldProps("email")["aria-invalid"]).toStrictEqual(
      undefined,
    );
    await act(async () => {
      await result.current.handleSubmit();
    });
    const props = result.current.getFieldProps("email");
    expect(props["aria-invalid"]).toStrictEqual(true);
    expect(props["aria-describedby"]).toStrictEqual(`${props.id}-error`);
  });
});
