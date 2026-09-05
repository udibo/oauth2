/**
 * Browser entry point. A React Router v7 **data mode** SPA
 * (`createBrowserRouter`) wrapped in `<OAuth2Provider>` so any route can read
 * auth state with `useOAuth2()` or gate itself with `<RequireAuth>`.
 *
 * @module
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";

import { OAuth2Provider } from "@udibo/oauth2/react";

import { browserClient } from "@/oauth2/browser-client.ts";
import { Layout } from "@/client/routes/layout.tsx";
import { Home } from "@/client/routes/home.tsx";
import { Login } from "@/client/routes/login.tsx";
import { SignUp } from "@/client/routes/signup.tsx";
import { Dashboard } from "@/client/routes/dashboard.tsx";
import { VerifyEmail } from "@/client/routes/verify-email.tsx";
import { ForgotPassword } from "@/client/routes/forgot-password.tsx";
import { ResetPassword } from "@/client/routes/reset-password.tsx";

const router = createBrowserRouter([
  {
    path: "/",
    Component: Layout,
    children: [
      { index: true, Component: Home },
      { path: "login", Component: Login },
      { path: "signup", Component: SignUp },
      { path: "dashboard", Component: Dashboard },
      { path: "verify-email", Component: VerifyEmail },
      { path: "forgot-password", Component: ForgotPassword },
      { path: "reset-password", Component: ResetPassword },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <OAuth2Provider client={browserClient}>
      <RouterProvider router={router} />
    </OAuth2Provider>
  </StrictMode>,
);
