# Documentation

`@udibo/oauth2` helps you add authentication and authorization to an
application. Choose who hosts sign-in first; that determines which parts of the
package you need.

## Use Udibo's identity service

Udibo hosts the sign-in flow and issues tokens. Your app handles its callback,
keeps its own session, and validates access to its API. You do not need to
implement password storage, MFA enrollment, or an authorization server.

**Private beta:** [join the waitlist](https://udibo.com). If you already have
access, start with [the integration guide](guides/use-udibo.md).

Then read [API protection](guides/protect-an-api.md) and
[environment configuration](guides/deploy-across-environments.md).

## Host authorization for your own app

Your app owns its users, login pages, and persistent storage. The package
provides OAuth2 protocol handling and optional identity flows.

1. [Run a complete local example](quickstart.md).
2. [Configure your authorization server](guides/become-an-oauth-provider.md).
3. [Add login over your database](guides/add-login.md).
4. [Prepare the application for deployment](guides/production-deployment.md).

Add only the features your application needs:

| Feature                         | Guide                                                         |
| ------------------------------- | ------------------------------------------------------------- |
| Social or enterprise OIDC login | [External sign-in](guides/social-sign-in.md)                  |
| TOTP and recovery codes         | [MFA](guides/add-mfa.md)                                      |
| Email codes and magic links     | [Passwordless sign-in](guides/passwordless.md)                |
| Existing password hashes        | [Password migration](guides/migrate-from-another-provider.md) |

These guides explain application integrations. Hosted-service administration,
commercial platform architecture, and internal Udibo operations are outside this
package's documentation.

## Testing and reference

- [React integration](guides/react.md): session state, rendering guards, and
  app-owned forms.
- [Integration testing](guides/testing.md): route fixtures, persistent store
  contracts, and browser checks.

- [Local identity provider](guides/run-a-local-identity-provider.md): exercise
  your client against a local OAuth2/OIDC server without a hosted account.
- [Deployment checklist](guides/hardening-checklist.md): review the boundaries
  your chosen integration uses.
- [Extension reference](trigger-points.md): callback and storage contracts.
- [Known limitations](known-limitations.md): supported behavior and constraints.
- [API reference](https://jsr.io/@udibo/oauth2/doc): exported types and methods.
- [Versioning and runtime support](stability.md).
- [Issue triage](triage.md) and [security disclosure](../SECURITY.md).
- [Agent index](../llms.txt) and [complete documentation](../llms-full.txt).

Code fences show one of three things: a runnable command, a self-contained
example, or integration wiring that explicitly declares app-owned dependencies.
A `declare const` represents something your application must supply; it is not
an implementation to paste into production.
