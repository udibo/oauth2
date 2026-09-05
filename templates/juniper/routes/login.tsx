import { Form, useNavigation } from "react-router";

import type { AnyParams, RouteProps } from "@udibo/juniper";

export interface LoginLoaderData {
  /** Sanitized same-origin path to resume after a successful sign-in. */
  returnTo: string;
}

export interface LoginActionData {
  error: string;
  returnTo: string;
}

export default function Login({
  loaderData,
  actionData,
}: RouteProps<AnyParams, LoginLoaderData, LoginActionData>) {
  const navigation = useNavigation();
  const isSubmitting = navigation.state === "submitting";
  const returnTo = actionData?.returnTo ?? loaderData.returnTo;

  return (
    <section>
      <title>Sign in</title>
      <h2>Sign in</h2>
      {actionData?.error && (
        <p role="alert" style={{ color: "crimson" }}>{actionData.error}</p>
      )}
      <Form method="post">
        <input type="hidden" name="return_to" value={returnTo} />
        <p>
          <label>
            Username <input name="username" autoComplete="username" required />
          </label>
        </p>
        <p>
          <label>
            Password{" "}
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
        </p>
        <button type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Signing in…" : "Sign in"}
        </button>
      </Form>
      <p>
        No account?{" "}
        <a href={`/signup?return_to=${encodeURIComponent(returnTo)}`}>
          Create one
        </a>
      </p>
    </section>
  );
}
