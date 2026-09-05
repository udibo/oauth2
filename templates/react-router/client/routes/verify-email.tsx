/**
 * Email-verification landing page — the target of the link the server logs to
 * its console on sign-up. Consumes the single-use token and reports the
 * outcome, distinguishing an expired link from an invalid one.
 *
 * @module
 */

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";

type Outcome = "verifying" | "success" | "expired" | "invalid";

const outcomes = new Map<string, Promise<Outcome>>();

function verifyToken(token: string): Promise<Outcome> {
  let outcome = outcomes.get(token);
  if (!outcome) {
    outcome = fetch("/identity/email/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token }),
    }).then(async (response) => {
      if (response.ok) return "success";
      const data = await response.json().catch(() => ({})) as {
        error?: string;
      };
      return data.error === "token_expired" ? "expired" : "invalid";
    }).catch(() => "invalid" as const);
    outcomes.set(token, outcome);
  }
  return outcome;
}

export function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const [outcome, setOutcome] = useState<Outcome>(
    token ? "verifying" : "invalid",
  );

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    verifyToken(token).then((result) => {
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
    </main>
  );
}
