import type { ClientInterface } from "../models/client.ts";
import type { Token } from "../models/token.ts";
import { AuthorizationCodeGrant } from "../server/grants/authorization-code.ts";
import { RefreshTokenGrant } from "../server/grants/refresh-token.ts";
import { AuthorizationServer } from "../server/authorization-server.ts";
import {
  createJwtAccessTokenGenerator,
  generateSigningKey,
  StaticSigningKeyProvider,
} from "../server/signing-keys.ts";
import { BasicScope } from "../models/scope.ts";

import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "./services.ts";

/** A person in a {@linkcode FakeTenant}. */
export interface FakeTenantUser {
  /** The subject every token and answer names. */
  id: string;
  /** The `username` introspection reports. */
  username: string;
  /** The `name` claim UserInfo reports. */
  name?: string;
  /** The `email` claim UserInfo reports. */
  email?: string;
  /** The `email_verified` claim UserInfo reports. Defaults to `true`. */
  emailVerified?: boolean;
  /** Permissions held tenant-wide, in every organization and on every resource. */
  permissions?: string[];
}

/** An OAuth2 application registered in a {@linkcode FakeTenant}. */
export interface FakeTenantClient extends ClientInterface {
  /** Omit for a public client. */
  secret?: string;
  /**
   * `"jwt"` issues RFC 9068 access tokens signed with the tenant's JWKS key,
   * for a resource server that validates locally. Defaults to `"opaque"`.
   */
  accessTokenFormat?: "opaque" | "jwt";
  /** A JWT access token's `aud`. Defaults to the client id. */
  audience?: string;
}

/** An organization in a {@linkcode FakeTenant}. */
export interface FakeTenantOrganization {
  /** The id `org_id` carries and every scoped answer is keyed by. */
  id: string;
  /** The handle `org_slug` carries. Never an authorization key. */
  slug: string;
}

/** A person's place in one organization. */
export interface FakeTenantMembership {
  /** The role slugs `org_roles` reports. */
  roles?: string[];
  /** Permissions held inside this organization only. */
  permissions?: string[];
}

/** Who a resource grant is for. */
export type FakeTenantSubject =
  | { type: "user"; id: string }
  | { type: "organization"; id: string };

/** Permissions on one resource instance, for one subject. */
export interface FakeTenantGrant {
  /** A type registered with {@linkcode FakeTenant.registerResourceType}, and your id for the instance. */
  resource: { type: string; id: string };
  /** A user, or an organization whose every member it admits. */
  subject: FakeTenantSubject;
  /** What the subject may do on that one resource. */
  permissions: string[];
}

/** How the next sign-in resolves. */
export interface FakeTenantSignIn {
  /**
   * The organization the person picks while signing in. Tokens issued from
   * that sign-in carry its `org_id`, `org_slug` and `org_roles`, and its
   * permissions join theirs. Omit for a sign-in with no organization.
   */
  organizationId?: string;
}

/** What {@linkcode FakeTenant.issueAccessToken} mints a token for. */
export interface FakeTenantTokenRequest {
  /** The registered client the token is issued to. */
  clientId: string;
  /** The person the token is for. */
  userId: string;
  /** The organization the token answers for. Omit for none. */
  organizationId?: string;
  /** The granted scope. Defaults to `openid`. */
  scope?: string;
}

/** Options for {@linkcode createFakeTenant}. */
export interface FakeTenantOptions {
  /**
   * The origin the tenant is served on, exactly as the app under test
   * configures its issuer. Every advertised endpoint and every JWT `iss` is
   * built from it.
   */
  issuer: string;
}

/**
 * A stand-in for a Udibo tenant, for testing an app that signs in against one
 * without running the identity service. It answers the tenant's protocol
 * surface — discovery, authorize, token, introspection, UserInfo, JWKS — and
 * the two authorization questions, `POST /api/check` and
 * `POST /api/check/batch`, with the same shapes a real tenant uses.
 *
 * Nothing here is interactive: {@linkcode signInAs} decides who the next
 * authorization request authenticates, and there is no consent step. Serve
 * {@linkcode fetch} on the origin passed as `issuer`.
 */
export interface FakeTenant {
  /** The origin this tenant answers as. */
  readonly issuer: string;
  /** Handles one request to the tenant. Serve it on {@linkcode issuer}. */
  fetch(request: Request): Promise<Response>;
  /** Registers an application. Throws on a duplicate id. */
  addClient(client: FakeTenantClient): Promise<void>;
  /** Adds a person. Throws on a duplicate id or username. */
  addUser(user: FakeTenantUser): Promise<void>;
  /** Adds an organization. Throws on a duplicate id. */
  addOrganization(organization: FakeTenantOrganization): void;
  /** Makes a person a member of an organization, replacing any earlier membership. */
  addMember(
    organizationId: string,
    userId: string,
    membership?: FakeTenantMembership,
  ): void;
  /** Ends a membership. Credentials issued in that organization stop answering for it. */
  removeMember(organizationId: string, userId: string): void;
  /** Registers a resource type, so `/api/check` accepts it. */
  registerResourceType(type: string): void;
  /** Adds a resource grant. */
  grant(grant: FakeTenantGrant): void;
  /**
   * Chooses who the next authorization requests authenticate as, until
   * called again. With nobody chosen, authorize answers `login_required`.
   */
  signInAs(userId: string | null, signIn?: FakeTenantSignIn): void;
  /**
   * Mints an access token without the browser flow, for testing an API
   * directly. JWT or opaque as the client is registered.
   */
  issueAccessToken(request: FakeTenantTokenRequest): Promise<string>;
}

const PATHS = {
  authorization: "/api/oauth2/authorize",
  token: "/api/oauth2/token",
  revocation: "/api/oauth2/revoke",
  introspection: "/api/oauth2/introspect",
  userinfo: "/api/oauth2/userinfo",
  jwks: "/api/oauth2/jwks",
} as const;

const MAX_PERMISSIONS = 50;
const MAX_BATCH_IDS = 100;

interface SignIn {
  userId: string;
  organizationId?: string;
}

interface Organization extends FakeTenantOrganization {
  members: Map<string, FakeTenantMembership>;
}

class TenantTokenService extends MemoryTokenService<
  FakeTenantClient,
  FakeTenantUser,
  BasicScope
> {
  constructor(
    options: ConstructorParameters<
      typeof MemoryTokenService<FakeTenantClient, FakeTenantUser, BasicScope>
    >[0],
    readonly organizationOf: (userId: string) => string | undefined,
    readonly recordCredential: (
      accessToken: string,
      organizationId: string | undefined,
    ) => void,
    readonly mintJwt: (
      client: FakeTenantClient,
      user: FakeTenantUser,
      scope: BasicScope | null | undefined,
      organizationId: string | undefined,
    ) => Promise<string>,
  ) {
    super(options);
  }

  override async generateAccessToken(
    client: FakeTenantClient,
    user: FakeTenantUser,
    scope?: BasicScope | null,
  ): Promise<string> {
    const organizationId = user ? this.organizationOf(user.id) : undefined;
    const accessToken = client.accessTokenFormat === "jwt" && user
      ? await this.mintJwt(client, user, scope, organizationId)
      : await super.generateAccessToken(client, user, scope);
    this.recordCredential(accessToken, organizationId);
    return accessToken;
  }
}

function problem(status: number, detail: string): Response {
  return Response.json({ status, detail }, {
    status,
    headers: { "content-type": "application/problem+json" },
  });
}

function asPermissions(value: unknown): string[] | undefined {
  const list = typeof value === "string" ? [value] : value;
  if (
    !Array.isArray(list) || list.length === 0 ||
    list.length > MAX_PERMISSIONS ||
    !list.every((entry) => typeof entry === "string" && entry.length > 0)
  ) {
    return undefined;
  }
  return list;
}

/**
 * Creates a {@linkcode FakeTenant}. Serve its `fetch` on the origin you pass
 * as `issuer`, then point the app under test at that origin.
 *
 * @example
 * ```ts
 * import { createFakeTenant } from "@udibo/oauth2/testing";
 *
 * const server = Deno.serve(
 *   { hostname: "127.0.0.1", port: 0, onListen() {} },
 *   (request) => tenant.fetch(request),
 * );
 * const tenant = await createFakeTenant({
 *   issuer: `http://127.0.0.1:${server.addr.port}`,
 * });
 * await tenant.addUser({ id: "user-1", username: "ada" });
 * tenant.signInAs("user-1");
 * await server.shutdown();
 * ```
 */
export async function createFakeTenant(
  options: FakeTenantOptions,
): Promise<FakeTenant> {
  const issuer = new URL(options.issuer).origin;
  const signingKeys = new StaticSigningKeyProvider(await generateSigningKey());
  const users = new Map<string, FakeTenantUser>();
  const organizations = new Map<string, Organization>();
  const resourceTypes = new Set<string>();
  const grants: FakeTenantGrant[] = [];
  const credentialOrganization = new Map<string, string | undefined>();
  let signedIn: SignIn | null = null;
  const pendingOrganization = new Map<string, string | undefined>();

  const membershipOf = (organizationId: string | undefined, userId: string) =>
    organizationId
      ? organizations.get(organizationId)?.members.get(userId)
      : undefined;

  const permissionsIn = (userId: string, organizationId?: string) =>
    new Set([
      ...users.get(userId)?.permissions ?? [],
      ...membershipOf(organizationId, userId)?.permissions ?? [],
    ]);

  const organizationClaims = (userId: string, organizationId?: string) => {
    const membership = membershipOf(organizationId, userId);
    if (!organizationId || !membership) return {};
    return {
      org_id: organizationId,
      org_slug: organizations.get(organizationId)!.slug,
      org_roles: membership.roles ?? [],
    };
  };

  const authorizationClaims = (userId: string, organizationId?: string) => {
    const claims = organizationClaims(userId, organizationId);
    return {
      permissions: [...permissionsIn(userId, claims.org_id)],
      ...claims,
    };
  };

  const userService = new MemoryUserService<FakeTenantUser>();
  const clientService = new MemoryClientService<
    FakeTenantClient,
    FakeTenantUser
  >(userService);
  const tokenService = new TenantTokenService(
    { clientService, userService },
    (userId) => pendingOrganization.get(userId),
    (accessToken, organizationId) =>
      credentialOrganization.set(accessToken, organizationId),
    (client, user, scope, organizationId) =>
      createJwtAccessTokenGenerator({
        signingKeys,
        issuer,
        audience: client.audience ?? client.id,
        userClaims: () => ({
          username: user.username,
          ...authorizationClaims(user.id, organizationId),
        }),
      })(client, user, scope),
  );
  const authorizationCodeService = new MemoryAuthorizationCodeService<
    FakeTenantClient,
    FakeTenantUser,
    BasicScope
  >({ clientService, userService });

  const server = new AuthorizationServer<
    FakeTenantClient,
    FakeTenantUser,
    BasicScope
  >({
    resolve: () => ({
      services: { clientService, tokenService },
      issuer,
      authorizationEndpoint: `${issuer}${PATHS.authorization}`,
      tokenEndpoint: `${issuer}${PATHS.token}`,
      revocationEndpoint: `${issuer}${PATHS.revocation}`,
      introspectionEndpoint: `${issuer}${PATHS.introspection}`,
      userinfoEndpoint: `${issuer}${PATHS.userinfo}`,
      jwksEndpoint: `${issuer}${PATHS.jwks}`,
    }),
    grants: {
      authorization_code: new AuthorizationCodeGrant({
        resolve: () => ({
          clientService,
          tokenService,
          authorizationCodeService,
        }),
        allowRefreshToken: true,
      }),
      refresh_token: new RefreshTokenGrant({
        resolve: () => ({ clientService, tokenService }),
      }),
    },
    signingKeys,
    scopesSupported: ["openid", "profile", "email", "offline_access"],
    userClaims: (user) => ({
      preferred_username: user.username,
      name: user.name,
      email: user.email,
      email_verified: user.email ? user.emailVerified ?? true : undefined,
      ...organizationClaims(
        user.id,
        signedIn?.userId === user.id ? signedIn.organizationId : undefined,
      ),
    }),
    introspectionClaims: (token) =>
      token.user
        ? authorizationClaims(
          token.user.id,
          credentialOrganization.get(token.accessToken),
        )
        : {},
  });

  const withPendingOrganization = async <T>(
    userId: string | undefined,
    organizationId: string | undefined,
    work: () => Promise<T>,
  ): Promise<T> => {
    if (!userId) return await work();
    pendingOrganization.set(userId, organizationId);
    try {
      return await work();
    } finally {
      pendingOrganization.delete(userId);
    }
  };

  const authenticated = async (
    request: Request,
  ): Promise<
    | { user: FakeTenantUser; organizationId?: string }
    | Response
  > => {
    let token: Token<FakeTenantClient, FakeTenantUser, BasicScope>;
    try {
      ({ token } = await server.authenticate(request));
    } catch (error) {
      return server.handleAuthError(error);
    }
    if (!token.user) {
      return problem(403, "A machine credential has no self to answer for.");
    }
    const organizationId = credentialOrganization.get(token.accessToken);
    return {
      user: token.user,
      organizationId: membershipOf(organizationId, token.user.id)
        ? organizationId
        : undefined,
    };
  };

  const resourcePermissions = (userId: string, type: string, id: string) => {
    const held = permissionsIn(userId);
    for (const grant of grants) {
      if (grant.resource.type !== type || grant.resource.id !== id) continue;
      const admits = grant.subject.type === "user"
        ? grant.subject.id === userId
        : Boolean(membershipOf(grant.subject.id, userId));
      if (admits) grant.permissions.forEach((p) => held.add(p));
    }
    return held;
  };

  const answer = (asked: string[], held: Set<string>) =>
    Object.fromEntries(asked.map((p) => [p, held.has(p)]));

  const check = async (request: Request): Promise<Response> => {
    const caller = await authenticated(request);
    if (caller instanceof Response) return caller;
    const body = await request.json().catch(() => null) as {
      permissions?: unknown;
      resource?: { type?: unknown; id?: unknown };
    } | null;
    const asked = asPermissions(body?.permissions);
    if (!asked) return problem(400, "permissions is invalid");
    const resource = body?.resource;
    if (resource === undefined) {
      return Response.json({
        subject: caller.user.id,
        resource: caller.organizationId
          ? { type: "organization", id: caller.organizationId }
          : null,
        results: answer(
          asked,
          permissionsIn(caller.user.id, caller.organizationId),
        ),
      });
    }
    if (typeof resource?.type !== "string" || typeof resource.id !== "string") {
      return problem(400, "resource is invalid");
    }
    if (resource.type === "organization") {
      if (!membershipOf(resource.id, caller.user.id)) {
        return problem(404, "Organization not found");
      }
      return Response.json({
        subject: caller.user.id,
        resource: { type: "organization", id: resource.id },
        results: answer(asked, permissionsIn(caller.user.id, resource.id)),
      });
    }
    if (!resourceTypes.has(resource.type)) {
      return problem(400, `resource.type "${resource.type}" is not registered`);
    }
    return Response.json({
      subject: caller.user.id,
      resource: { type: resource.type, id: resource.id },
      results: answer(
        asked,
        resourcePermissions(caller.user.id, resource.type, resource.id),
      ),
    });
  };

  const checkBatch = async (request: Request): Promise<Response> => {
    const caller = await authenticated(request);
    if (caller instanceof Response) return caller;
    const body = await request.json().catch(() => null) as {
      permissions?: unknown;
      resource?: { type?: unknown; ids?: unknown };
    } | null;
    const asked = asPermissions(body?.permissions);
    if (!asked) return problem(400, "permissions is invalid");
    const type = body?.resource?.type;
    const ids = body?.resource?.ids;
    if (
      typeof type !== "string" || !Array.isArray(ids) || ids.length === 0 ||
      ids.length > MAX_BATCH_IDS ||
      !ids.every((id) => typeof id === "string" && id.length > 0)
    ) {
      return problem(400, "resource is invalid");
    }
    if (!resourceTypes.has(type)) {
      return problem(400, `resource.type "${type}" is not registered`);
    }
    return Response.json({
      subject: caller.user.id,
      resource: { type },
      results: Object.fromEntries(
        ids.map((id: string) => [
          id,
          answer(asked, resourcePermissions(caller.user.id, type, id)),
        ]),
      ),
    });
  };

  const signInOfCode = new Map<string, SignIn>();
  const signInOfRefreshToken = new Map<string, SignIn>();

  const authorize = async (request: Request): Promise<Response> => {
    const chosen = signedIn;
    const response = await server.handleAuthorizeRequest(
      request,
      () => {
        const user = chosen ? users.get(chosen.userId) : undefined;
        return Promise.resolve(user ? { user } : null);
      },
    );
    const location = response.headers.get("location");
    const code = location ? new URL(location).searchParams.get("code") : null;
    if (code && chosen) signInOfCode.set(code, chosen);
    return response;
  };

  const token = async (request: Request): Promise<Response> => {
    const form = await request.clone().formData().catch(() => null);
    const code = form?.get("code");
    const refreshToken = form?.get("refresh_token");
    const signIn = typeof code === "string"
      ? signInOfCode.get(code)
      : typeof refreshToken === "string"
      ? signInOfRefreshToken.get(refreshToken)
      : undefined;
    const response = await withPendingOrganization(
      signIn?.userId,
      signIn?.organizationId,
      () => server.handleTokenRequest(request),
    );
    if (response.ok && signIn) {
      const issued = await response.clone().json() as {
        refresh_token?: string;
      };
      if (issued.refresh_token) {
        signInOfRefreshToken.set(issued.refresh_token, signIn);
      }
    }
    return response;
  };

  const routes: Record<string, (request: Request) => Promise<Response>> = {
    "GET /.well-known/oauth-authorization-server": (r) =>
      server.handleMetadataRequest(r),
    "GET /.well-known/openid-configuration": (r) =>
      server.handleOidcMetadataRequest(r),
    [`GET ${PATHS.authorization}`]: authorize,
    [`POST ${PATHS.token}`]: token,
    [`POST ${PATHS.revocation}`]: (r) => server.handleRevocationRequest(r),
    [`POST ${PATHS.introspection}`]: (r) =>
      server.handleIntrospectionRequest(r),
    [`GET ${PATHS.userinfo}`]: (r) => server.handleUserInfoRequest(r),
    [`POST ${PATHS.userinfo}`]: (r) => server.handleUserInfoRequest(r),
    [`GET ${PATHS.jwks}`]: (r) => server.handleJwksRequest(r),
    "POST /api/check": check,
    "POST /api/check/batch": checkBatch,
  };

  return {
    issuer,
    fetch: (request) => {
      const route =
        routes[`${request.method} ${new URL(request.url).pathname}`];
      return route
        ? route(request)
        : Promise.resolve(problem(404, "Not found"));
    },
    addClient: async ({ secret, ...client }) => {
      await clientService.add(
        {
          grants: ["authorization_code", "refresh_token"],
          ...client,
        },
        secret,
      );
    },
    addUser: async (user) => {
      await userService.add(user, crypto.randomUUID());
      users.set(user.id, user);
    },
    addOrganization: (organization) => {
      if (organizations.has(organization.id)) {
        throw new Error(`Organization "${organization.id}" already exists`);
      }
      organizations.set(organization.id, {
        ...organization,
        members: new Map(),
      });
    },
    addMember: (organizationId, userId, membership = {}) => {
      const organization = organizations.get(organizationId);
      if (!organization) {
        throw new Error(`Organization "${organizationId}" does not exist`);
      }
      organization.members.set(userId, membership);
    },
    removeMember: (organizationId, userId) => {
      organizations.get(organizationId)?.members.delete(userId);
    },
    registerResourceType: (type) => {
      resourceTypes.add(type);
    },
    grant: (grant) => {
      grants.push(grant);
    },
    signInAs: (userId, signIn = {}) => {
      signedIn = userId ? { userId, ...signIn } : null;
    },
    issueAccessToken: async (request) => {
      const client = await clientService.get(request.clientId);
      const user = users.get(request.userId);
      if (!client) {
        throw new Error(`Client "${request.clientId}" does not exist`);
      }
      if (!user) throw new Error(`User "${request.userId}" does not exist`);
      const scope = new BasicScope(request.scope ?? "openid");
      return await withPendingOrganization(
        user.id,
        request.organizationId,
        async () => {
          const accessToken = await tokenService.generateAccessToken(
            client,
            user,
            scope,
          );
          await tokenService.save({
            client,
            user,
            scope,
            accessToken,
            accessTokenExpiresAt: await tokenService.accessTokenExpiresAt(
              client,
              user,
              scope,
            ),
          });
          return accessToken;
        },
      );
    },
  };
}
