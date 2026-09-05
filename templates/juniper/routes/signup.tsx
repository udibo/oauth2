import { Form, useNavigation } from "react-router";

import type { AnyParams, RouteProps } from "@udibo/juniper";

export interface SignupLoaderData {
  /** Sanitized same-origin path to resume after a successful sign-up. */
  returnTo: string;
}

export interface SignupActionData {
  error: string;
  returnTo: string;
}

export default function Signup({
  loaderData,
  actionData,
}: RouteProps<AnyParams, SignupLoaderData, SignupActionData>) {
  const navigation = useNavigation();
  const isSubmitting = navigation.state === "submitting";
  const returnTo = actionData?.returnTo ?? loaderData.returnTo;

  return (
    <section>
      <title>Create account</title>
      <h2>Create account</h2>
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
            Name <input name="name" autoComplete="name" required />
          </label>
        </p>
        <p>
          <label>
            Password{" "}
            <input
              name="password"
              type="password"
              autoComplete="new-password"
              minLength={8}
              required
            />
          </label>
        </p>
        <button type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Creating account…" : "Create account"}
        </button>
      </Form>
      <p>
        Already have an account?{" "}
        <a href={`/login?return_to=${encodeURIComponent(returnTo)}`}>
          Sign in
        </a>
      </p>
    </section>
  );
}
