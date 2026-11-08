/**
 * Email-verification landing page — the target of the link the server logs to
 * its console on sign-up. Consumes the single-use token and reports the
 * outcome, distinguishing an expired link from an invalid one. The server only
 * spends the link for the account it was sent to, so a visitor who is signed
 * out, or signed in as someone else, is asked to sign in and comes back to the
 * same link.
 *
 * @module
 */

import { type ReactNode, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import type { Route } from "./+types/verify-email";

type Outcome =
  | "verifying"
  | "success"
  | "expired"
  | "invalid"
  | "sign-in-required"
  | "wrong-account";

const REFUSALS: Record<string, Outcome> = {
  token_expired: "expired",
  sign_in_required: "sign-in-required",
  wrong_account: "wrong-account",
};
const RETRYABLE = new Set<Outcome>(["sign-in-required", "wrong-account"]);

const outcomes = new Map<string, Promise<Outcome>>();

function verifyToken(token: string): Promise<Outcome> {
  let outcome = outcomes.get(token);
  if (!outcome) {
    outcome = fetch("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    })
      .then(async (response) => {
        if (response.ok) return "success";
        const data = (await response.json().catch(() => ({}))) as {
          error?: string;
        };
        return REFUSALS[data.error ?? ""] ?? "invalid";
      })
      .catch(() => "invalid" as const)
      .then((result) => {
        if (RETRYABLE.has(result)) outcomes.delete(token);
        return result;
      });
    outcomes.set(token, outcome);
  }
  return outcome;
}

function signInTo(token: string | null): string {
  const back = `/verify-email?token=${encodeURIComponent(token ?? "")}`;
  return `/login?return_to=${encodeURIComponent(back)}`;
}

export function meta(): Route.MetaDescriptors {
  return [{ title: "Verify email" }];
}

export default function VerifyEmail(): ReactNode {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const [outcome, setOutcome] = useState<Outcome>(
    token ? "verifying" : "invalid",
  );

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    void verifyToken(token).then((result) => {
      if (!cancelled) setOutcome(result);
    });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <main>
      <h1>Verify email</h1>
      {outcome === "verifying" && <p>Verifying…</p>}
      {outcome === "success" && (
        <p>
          Email verified. Head to your <Link to="/dashboard">dashboard</Link>.
        </p>
      )}
      {outcome === "expired" && (
        <p>That link has expired. Sign in and request a new one.</p>
      )}
      {outcome === "invalid" && <p>That link is invalid or already used.</p>}
      {outcome === "sign-in-required" && (
        <p>
          <Link to={signInTo(token)}>Sign in</Link> to the account this link was
          sent for to finish verifying your email.
        </p>
      )}
      {outcome === "wrong-account" && (
        <p>
          This link was sent for a different account.{" "}
          <Link to={signInTo(token)}>Sign in</Link> as that account to finish
          verifying it.
        </p>
      )}
    </main>
  );
}
