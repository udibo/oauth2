import { useState } from "react";
import { RequireAuth, useOAuth2 } from "@udibo/oauth2/react";

interface ApiResult {
  status: number;
  body: string;
}

function Session() {
  const { user, fetch } = useOAuth2();
  const [result, setResult] = useState<ApiResult | null>(null);

  const callApi = async () => {
    const res = await fetch("/api/me");
    setResult({ status: res.status, body: await res.text() });
  };

  return (
    <section>
      <h2>Profile</h2>
      <p>Your session, as reported by the BFF:</p>
      <pre style={{ background: "#f4f4f4", padding: "0.5rem" }}>
        {JSON.stringify(user, null, 2)}
      </pre>
      <button type="button" onClick={callApi}>Call the protected API</button>
      {result && (
        <pre
          style={{ background: "#f4f4f4", padding: "0.5rem", overflow: "auto" }}
        >
          {result.status} {result.body}
        </pre>
      )}
    </section>
  );
}

export default function Profile() {
  return (
    <>
      <title>Profile</title>
      <RequireAuth fallback={<p>Redirecting to sign in…</p>}>
        <Session />
      </RequireAuth>
    </>
  );
}
