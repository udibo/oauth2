import { Link } from "react-router";
import { useOAuth2 } from "@udibo/oauth2/react";

export default function Home() {
  const { isAuthenticated, isLoading, user, login, logout } = useOAuth2();

  if (isLoading) return <p>Loading…</p>;

  return (
    <>
      <meta name="description" content="Home page" />
      {isAuthenticated
        ? (
          <>
            <p>
              Signed in as{" "}
              <strong>
                {String(user?.name ?? user?.username ?? user?.sub ?? "")}
              </strong>.
            </p>
            <p>
              <Link to="/profile">View your profile</Link>
            </p>
            <button
              type="button"
              onClick={() => logout({ returnTo: "/logout" })}
            >
              Sign out
            </button>
          </>
        )
        : (
          <>
            <p>You are signed out.</p>
            <button type="button" onClick={() => login()}>Sign in</button>
            <p>
              No account? <a href="/signup">Create one</a>
            </p>
          </>
        )}
    </>
  );
}
