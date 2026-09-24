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
import { InvalidRequestError } from "../errors.ts";
import { safeReturnTo } from "../utils/url.ts";

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
  /**
   * The `name` claim UserInfo reports, and the name the organization API's
   * member listing gives the person. The listing falls back to `username`.
   */
  name?: string;
  /**
   * The `email` claim UserInfo reports. An invitation to this address offers
   * the person a pending membership rather than an invitation.
   */
  email?: string;
  /**
   * The `email_verified` claim UserInfo reports. Defaults to `true`. While it
   * is `false`, invitations to the address stay hidden from the person's
   * offers and cannot be accepted.
   */
  emailVerified?: boolean;
  /** Permissions held tenant-wide, in every organization and on every resource. */
  permissions?: string[];
  /**
   * The person's own metadata bucket, as `GET /api/account` first reports
   * it. Defaults to `{}`.
   */
  userMetadata?: Record<string, unknown>;
  /**
   * Whether the person has a password. Defaults to `true`. Without one, a
   * linked account is their only way in, and the account API refuses to
   * disconnect the last of them.
   */
  hasPassword?: boolean;
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
  /**
   * Whose application this is. Defaults to `"first-party"`: its credentials
   * belong to the login session they were issued from, so a later sign-in in
   * that browser revokes them, revoking one ends the session, and ending the
   * session revokes them. A `"third-party"` application's credentials only
   * name that session as the one they came from, and outlive it.
   */
  type?: "first-party" | "third-party";
}

/** An organization in a {@linkcode FakeTenant}. */
export interface FakeTenantOrganization {
  /** The id `org_id` carries and every scoped answer is keyed by. */
  id: string;
  /** The handle `org_slug` carries. Never an authorization key. */
  slug: string;
  /** The display name `/api/memberships` reports. Defaults to the slug. */
  name?: string;
}

/** A person's place in one organization. */
export interface FakeTenantMembership {
  /**
   * The roles the membership holds, as `org_roles`, `/api/memberships` and the
   * organization API report them. `owner`, `admin` and `member` are the
   * built-in tiers. `owner` and `admin` may manage the organization through
   * its API, and only `owner` may delete it or deal in the `owner` tier.
   * Defaults to `["member"]`, because a membership on a real tenant always
   * holds a role. An empty list is also read as `["member"]`.
   */
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

/** An organization role your tenant defines beside the built-in tiers. */
export interface FakeTenantOrganizationRole {
  /** The role a membership, an invitation or `org_roles` names. */
  slug: string;
  /** How the role is named to people. Defaults to the slug. */
  name?: string;
}

/** An external account a person can sign in with. */
export interface FakeTenantLinkedAccount {
  /** The provider's key, such as `google` or `github`. */
  provider: string;
  /** How the provider is named to the person. Defaults to the key. */
  displayName?: string;
  /** The address the provider reported, if any. */
  email?: string | null;
}

/** How the next sign-in resolves. */
export interface FakeTenantSignIn {
  /**
   * The organization the person picks while signing in. Tokens issued from
   * that sign-in carry its `org_id`, `org_slug` and `org_roles`, and its
   * permissions join theirs. Omit it and a person in exactly one organization
   * gets that one, as on a real tenant; a person in several gets none. An
   * `organization` parameter on the authorization request, by id or slug,
   * overrides both for that credential, and is refused with
   * `invalid_request` when the person is not a member.
   */
  organizationId?: string;
  /** The browser `GET /api/account/sessions` reports for this sign-in. */
  userAgent?: string;
  /** The address `GET /api/account/sessions` reports for this sign-in. */
  ipAddress?: string;
}

/** What {@linkcode FakeTenant.issueAccessToken} mints a token for. */
export interface FakeTenantTokenRequest {
  /** The registered client the token is issued to. */
  clientId: string;
  /** The person the token is for. */
  userId: string;
  /**
   * The organization the token answers for. Omit it and a person in exactly
   * one organization gets that one; a person in several gets none.
   */
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
 * A stand-in for a Udibo Identity tenant, for testing an app that signs in against one
 * without running the identity service. It answers the tenant's protocol
 * surface — discovery, authorize, token, introspection, UserInfo, JWKS — the
 * caller's own `GET /api/memberships`, the two authorization questions,
 * `POST /api/check` and `POST /api/check/batch`, the organization API under
 * `/api/organizations`, and the account API under `/api/account`, with the
 * same shapes and refusals a real tenant uses.
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
  /**
   * Makes a person a member of an organization, replacing any earlier
   * membership or offer there. Throws when the organization does not exist.
   */
  addMember(
    organizationId: string,
    userId: string,
    membership?: FakeTenantMembership,
  ): void;
  /**
   * Ends a membership and withdraws any offer the person holds there. From
   * then on introspection and `/api/check` stop answering for that
   * organization on credentials issued in it, and UserInfo drops its `org_*`
   * claims; a JWT access token or id_token already minted keeps its claims
   * until it expires.
   */
  removeMember(organizationId: string, userId: string): void;
  /**
   * Defines an organization role beside the built-in tiers, so invitations
   * may offer it and `member-roles` lists it. Throws on a built-in slug.
   */
  defineOrganizationRole(role: FakeTenantOrganizationRole): void;
  /** Registers a resource type, so `/api/check` accepts it. */
  registerResourceType(type: string): void;
  /** Adds a resource grant. */
  grant(grant: FakeTenantGrant): void;
  /**
   * Links an external account to a person, as the account API lists it, and
   * returns its id. Throws when the person does not exist.
   */
  linkAccount(userId: string, account: FakeTenantLinkedAccount): string;
  /**
   * Chooses who the next authorization requests authenticate as, until
   * called again. With nobody chosen, authorize answers `access_denied`.
   *
   * Each call is a new browser: the first authorization after it starts a
   * login session, which the account API lists, and later ones reuse it until
   * that session is ended. When a first-party application signs in again in
   * that browser, the credentials the session issued before are revoked.
   */
  signInAs(userId: string | null, signIn?: FakeTenantSignIn): void;
  /**
   * Mints an access token without the browser flow, for testing an API
   * directly. JWT or opaque as the client is registered. It belongs to no
   * login session. Throws when the client or user does not exist.
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
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 100;
const METADATA_MAX_BYTES = 16 * 1024;
const METADATA_MAX_DEPTH = 8;
const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const RETURN_TO_MAX_LENGTH = 2048;
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_CHARACTERS = /\p{Cc}/u;

const BUILT_IN_ROLES: readonly { slug: string; name: string }[] = [
  { slug: "owner", name: "Owner" },
  { slug: "admin", name: "Admin" },
  { slug: "member", name: "Member" },
];
const OWNER = "owner";
const MANAGER_ROLES: readonly string[] = ["owner", "admin"];
const DEFAULT_ROLES: readonly string[] = ["member"];

const ORGANIZATION_NOT_FOUND = "Organization not found";

interface Issuance {
  organizationId?: string;
  sessionId?: string;
}

interface SignIn extends Issuance {
  userId: string;
}

interface Credential extends Issuance {
  boundSessionId?: string;
  refreshToken?: string;
  signIn?: SignIn;
}

interface ChosenSignIn extends FakeTenantSignIn {
  userId: string;
  sessionId?: string;
}

interface MembershipGrant {
  id: string;
  organizationId: string;
  userId: string;
  role: string;
  invitedByUserId: string | null;
  acceptedAt: Date | null;
  returnTo: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface Organization {
  id: string;
  slug: string;
  name: string;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  grants: MembershipGrant[];
  permissions: Map<string, string[]>;
}

interface Invitation {
  id: string;
  organizationId: string;
  email: string;
  role: string;
  invitedByUserId: string | null;
  expiresAt: Date;
  acceptedAt: Date | null;
  acceptedByUserId: string | null;
  returnTo: string | null;
  createdAt: Date;
  updatedAt: Date;
  deletedAt: Date | null;
}

interface LoginSession {
  id: string;
  userId: string;
  createdAt: Date;
  lastActiveAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
}

interface LinkedAccount {
  id: string;
  userId: string;
  provider: string;
  displayName: string;
  email: string | null;
  createdAt: Date;
}

interface Caller {
  user: FakeTenantUser;
  organizationId?: string;
  accessToken: string;
}

type Route = (
  request: Request,
  params: string[],
) => Promise<Response>;

class TenantTokenService extends MemoryTokenService<
  FakeTenantClient,
  FakeTenantUser,
  BasicScope
> {
  constructor(
    options: ConstructorParameters<
      typeof MemoryTokenService<FakeTenantClient, FakeTenantUser, BasicScope>
    >[0],
    readonly issuanceOf: (userId: string) => Issuance | undefined,
    readonly recordCredential: (
      accessToken: string,
      issuance: Issuance,
      client: FakeTenantClient,
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
    const issuance = (user ? this.issuanceOf(user.id) : undefined) ?? {};
    const accessToken = client.accessTokenFormat === "jwt" && user
      ? await this.mintJwt(client, user, scope, issuance.organizationId)
      : await super.generateAccessToken(client, user, scope);
    this.recordCredential(accessToken, issuance, client);
    return accessToken;
  }
}

function problem(
  status: number,
  detail: string,
  extensions: Record<string, unknown> = {},
): Response {
  return Response.json({ status, detail, ...extensions }, {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function jsonBody(request: Request): Promise<unknown> {
  const text = await request.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

async function isEmptyBody(request: Request): Promise<boolean> {
  const text = await request.text();
  if (!text.trim()) return true;
  try {
    const body = JSON.parse(text);
    return isRecord(body) && Object.keys(body).length === 0;
  } catch {
    return false;
  }
}

function depthOf(value: unknown): number {
  if (value === null || typeof value !== "object") return 0;
  const children = Array.isArray(value) ? value : Object.values(value);
  return 1 + Math.max(0, ...children.map(depthOf));
}

function metadataProblem(value: unknown): string | undefined {
  if (!isRecord(value)) return "Metadata must be a JSON object";
  if (depthOf(value) > METADATA_MAX_DEPTH) {
    return `Metadata must not nest deeper than ${METADATA_MAX_DEPTH} levels`;
  }
  const json = JSON.stringify(value);
  if (new TextEncoder().encode(json).length > METADATA_MAX_BYTES) {
    return `Metadata must be at most ${METADATA_MAX_BYTES} bytes`;
  }
  if (json.includes("\\u0000")) {
    return "Metadata must not contain NUL characters";
  }
  return undefined;
}

function nameProblem(value: unknown): string | undefined {
  if (
    typeof value !== "string" || value.length < 1 || value.length > 100 ||
    CONTROL_CHARACTERS.test(value)
  ) {
    return "name must be 1 to 100 characters with no control characters";
  }
  return undefined;
}

function slugProblem(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 100 || !SLUG.test(value)) {
    return "Must be lowercase letters, numbers and single hyphens";
  }
  return undefined;
}

function invalid(field: string, message: string): Response {
  return problem(400, message, { fieldErrors: { [field]: message } });
}

function iso(date: Date | null): string | null {
  return date ? date.toISOString() : null;
}

function encodeCursor(id: string, direction: "next" | "prev"): string {
  return btoa(JSON.stringify({ id, direction }));
}

function decodeCursor(
  value: string | null,
): { id: string; direction: "next" | "prev" } | null {
  if (!value) return null;
  try {
    const cursor = JSON.parse(atob(value));
    return typeof cursor?.id === "string" &&
        (cursor.direction === "next" || cursor.direction === "prev")
      ? cursor
      : null;
  } catch {
    return null;
  }
}

function page<T extends { id: string }>(
  rows: T[],
  request: Request,
): {
  data: T[];
  cursors: { next: string | null; prev: string | null };
  hasMore: boolean;
} {
  const params = new URL(request.url).searchParams;
  const requested = Number(params.get("limit") ?? DEFAULT_PAGE_SIZE);
  const limit = Number.isFinite(requested)
    ? Math.min(Math.max(Math.floor(requested), 1), MAX_PAGE_SIZE)
    : DEFAULT_PAGE_SIZE;
  const sorted = [...rows].sort((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0
  );
  const cursor = decodeCursor(params.get("cursor"));
  let data: T[];
  let hasMore: boolean;
  if (cursor?.direction === "prev") {
    const before = sorted.filter((row) => row.id < cursor.id);
    data = before.slice(-limit);
    hasMore = before.length > limit;
  } else {
    const after = cursor ? sorted.filter((row) => row.id > cursor.id) : sorted;
    data = after.slice(0, limit);
    hasMore = after.length > limit;
  }
  if (data.length === 0) {
    return { data, cursors: { next: null, prev: null }, hasMore: false };
  }
  const first = data[0].id;
  return {
    data,
    cursors: {
      next: encodeCursor(data[data.length - 1].id, "next"),
      prev: sorted.some((row) => row.id < first)
        ? encodeCursor(first, "prev")
        : null,
    },
    hasMore,
  };
}

function noStore(response: Response): Response {
  response.headers.set("cache-control", "no-store");
  return response;
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
  const userMetadata = new Map<string, Record<string, unknown>>();
  const organizations = new Map<string, Organization>();
  const definedRoles = new Map<string, string>();
  const invitations = new Map<string, Invitation>();
  const resourceTypes = new Set<string>();
  const grants: FakeTenantGrant[] = [];
  const loginSessions = new Map<string, LoginSession>();
  const linkedAccounts = new Map<string, LinkedAccount>();
  const credentials = new Map<string, Credential>();
  const redirectOrigins = new Set<string>();
  let signedIn: ChosenSignIn | null = null;
  const pendingIssuance = new Map<string, Issuance>();

  const acceptedRoles = (organizationId: string | undefined, userId: string) =>
    organizationId
      ? organizations.get(organizationId)?.grants
        .filter((grant) => grant.userId === userId && grant.acceptedAt)
        .map((grant) => grant.role) ?? []
      : [];

  const isMember = (organizationId: string | undefined, userId: string) =>
    acceptedRoles(organizationId, userId).length > 0;

  const holdsAny = (
    organizationId: string,
    userId: string,
    roles: readonly string[],
  ) =>
    acceptedRoles(organizationId, userId).some((role) => roles.includes(role));

  const permissionsIn = (userId: string, organizationId?: string) =>
    new Set([
      ...users.get(userId)?.permissions ?? [],
      ...isMember(organizationId, userId)
        ? organizations.get(organizationId!)!.permissions.get(userId) ?? []
        : [],
    ]);

  const organizationClaims = (userId: string, organizationId?: string) => {
    if (!organizationId || !isMember(organizationId, userId)) return {};
    return {
      org_id: organizationId,
      org_slug: organizations.get(organizationId)!.slug,
      org_roles: acceptedRoles(organizationId, userId),
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
    (userId) => pendingIssuance.get(userId),
    (accessToken, issuance, client) =>
      credentials.set(accessToken, {
        ...issuance,
        boundSessionId: client.type === "third-party"
          ? undefined
          : issuance.sessionId,
      }),
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
          credentials.get(token.accessToken)?.organizationId,
        )
        : {},
  });

  const withIssuance = async <T>(
    userId: string | undefined,
    issuance: Issuance,
    work: () => Promise<T>,
  ): Promise<T> => {
    if (!userId) return await work();
    pendingIssuance.set(userId, issuance);
    try {
      return await work();
    } finally {
      pendingIssuance.delete(userId);
    }
  };

  const authenticated = async (
    request: Request,
    machineRefusal: Record<string, unknown> = {},
  ): Promise<Caller | Response> => {
    let token: Token<FakeTenantClient, FakeTenantUser, BasicScope>;
    try {
      ({ token } = await server.authenticate(request));
    } catch (error) {
      return server.handleAuthError(error);
    }
    if (!token.user) {
      return problem(
        403,
        "A machine credential has no self to answer for.",
        machineRefusal,
      );
    }
    const user = users.get(token.user.id) ?? token.user;
    const organizationId = credentials.get(token.accessToken)?.organizationId;
    return {
      user,
      organizationId: isMember(organizationId, user.id)
        ? organizationId
        : undefined,
      accessToken: token.accessToken,
    };
  };

  const resourcePermissions = (userId: string, type: string, id: string) => {
    const held = permissionsIn(userId);
    for (const grant of grants) {
      if (grant.resource.type !== type || grant.resource.id !== id) continue;
      const admits = grant.subject.type === "user"
        ? grant.subject.id === userId
        : isMember(grant.subject.id, userId);
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
      if (!organizations.has(resource.id)) {
        return problem(404, ORGANIZATION_NOT_FOUND);
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

  const soleOrganizationOf = (userId: string) => {
    const joined = [...organizations.values()].filter((organization) =>
      isMember(organization.id, userId)
    );
    return joined.length === 1 ? joined[0].id : undefined;
  };

  const requestedOrganization = (requested: string, userId: string) => {
    const organization = organizations.get(requested) ??
      [...organizations.values()].find((o) => o.slug === requested);
    if (!organization || !isMember(organization.id, userId)) {
      throw new InvalidRequestError("organization is not available");
    }
    return organization.id;
  };

  const memberships = async (request: Request): Promise<Response> => {
    const caller = await authenticated(request);
    if (caller instanceof Response) return caller;
    return Response.json({
      memberships: [...organizations.values()]
        .filter((organization) => isMember(organization.id, caller.user.id))
        .map((organization) => ({
          org_id: organization.id,
          org_slug: organization.slug,
          name: organization.name,
          roles: acceptedRoles(organization.id, caller.user.id),
        })),
      cursor: null,
    });
  };

  const liveSessionOf = (chosen: ChosenSignIn): string => {
    const now = new Date();
    const existing = chosen.sessionId
      ? loginSessions.get(chosen.sessionId)
      : undefined;
    if (existing) {
      existing.lastActiveAt = now;
      return existing.id;
    }
    const session: LoginSession = {
      id: crypto.randomUUID(),
      userId: chosen.userId,
      createdAt: now,
      lastActiveAt: now,
      ipAddress: chosen.ipAddress ?? null,
      userAgent: chosen.userAgent ?? null,
    };
    loginSessions.set(session.id, session);
    chosen.sessionId = session.id;
    return session.id;
  };

  const authorize = async (request: Request): Promise<Response> => {
    const chosen = signedIn;
    const requested = new URL(request.url).searchParams.get("organization");
    let issued: SignIn | undefined;
    const response = await server.handleAuthorizeRequest(
      request,
      () => {
        const user = chosen ? users.get(chosen.userId) : undefined;
        if (!chosen || !user) return Promise.resolve(null);
        const organizationId = requested
          ? requestedOrganization(requested, user.id)
          : chosen.organizationId ?? soleOrganizationOf(user.id);
        issued = {
          userId: user.id,
          organizationId,
          sessionId: liveSessionOf(chosen),
        };
        return Promise.resolve({ user });
      },
    );
    const location = response.headers.get("location");
    const code = location ? new URL(location).searchParams.get("code") : null;
    if (code && issued) signInOfCode.set(code, issued);
    return response;
  };

  const isLive = async (accessToken: string) =>
    await tokenService.getToken(accessToken) !== undefined;

  const liveCredentials = async (
    matches: (credential: Credential, accessToken: string) => boolean,
  ): Promise<[string, Credential][]> => {
    const live: [string, Credential][] = [];
    for (const [accessToken, credential] of credentials) {
      if (matches(credential, accessToken) && await isLive(accessToken)) {
        live.push([accessToken, credential]);
      }
    }
    return live;
  };

  const revokeBoundTo = async (sessionId: string, keep?: string) => {
    for (const [accessToken, credential] of credentials) {
      if (credential.boundSessionId !== sessionId || accessToken === keep) {
        continue;
      }
      await tokenService.revoke(accessToken);
      credentials.delete(accessToken);
    }
  };

  const endSession = async (sessionId: string) => {
    loginSessions.delete(sessionId);
    await revokeBoundTo(sessionId);
  };

  const endSessionsOfRevoked = async (
    wereLive: [string, Credential][],
  ): Promise<void> => {
    for (const [accessToken, credential] of wereLive) {
      if (await isLive(accessToken)) continue;
      credentials.delete(accessToken);
      if (credential.boundSessionId) {
        await endSession(credential.boundSessionId);
      }
    }
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
    const family = typeof refreshToken === "string" && signIn
      ? await liveCredentials((credential) => credential.signIn === signIn)
      : [];
    const response = await withIssuance(
      signIn?.userId,
      { organizationId: signIn?.organizationId, sessionId: signIn?.sessionId },
      () => server.handleTokenRequest(request),
    );
    if (!response.ok) {
      await endSessionsOfRevoked(family);
      return response;
    }
    if (signIn) {
      const session = signIn.sessionId
        ? loginSessions.get(signIn.sessionId)
        : undefined;
      if (session) session.lastActiveAt = new Date();
      const issued = await response.clone().json() as {
        access_token: string;
        refresh_token?: string;
      };
      const credential = credentials.get(issued.access_token);
      if (credential) {
        credential.signIn = signIn;
        credential.refreshToken = issued.refresh_token;
      }
      if (issued.refresh_token) {
        signInOfRefreshToken.set(issued.refresh_token, signIn);
      }
      if (typeof code === "string" && credential?.boundSessionId) {
        await revokeBoundTo(credential.boundSessionId, issued.access_token);
      }
    }
    return response;
  };

  const revocation = async (request: Request): Promise<Response> => {
    const form = await request.clone().formData().catch(() => null);
    const value = form?.get("token");
    const presented = typeof value === "string"
      ? await liveCredentials((credential, accessToken) =>
        accessToken === value || credential.refreshToken === value
      )
      : [];
    const response = await server.handleRevocationRequest(request);
    await endSessionsOfRevoked(presented);
    return response;
  };

  const organizationJson = (organization: Organization) => ({
    id: organization.id,
    name: organization.name,
    slug: organization.slug,
    metadata: organization.metadata,
    createdAt: iso(organization.createdAt),
    updatedAt: iso(organization.updatedAt),
    deletedAt: null,
  });

  const grantJson = (grant: MembershipGrant) => ({
    id: grant.id,
    organizationId: grant.organizationId,
    role: grant.role,
    userId: grant.userId,
    invitedByUserId: grant.invitedByUserId,
    acceptedAt: iso(grant.acceptedAt),
    returnTo: grant.returnTo,
    createdAt: iso(grant.createdAt),
    updatedAt: iso(grant.updatedAt),
    deletedAt: null,
  });

  const invitationJson = (invitation: Invitation) => ({
    id: invitation.id,
    organizationId: invitation.organizationId,
    email: invitation.email,
    role: invitation.role,
    invitedByUserId: invitation.invitedByUserId,
    expiresAt: iso(invitation.expiresAt),
    acceptedAt: iso(invitation.acceptedAt),
    acceptedByUserId: invitation.acceptedByUserId,
    returnTo: invitation.returnTo,
    createdAt: iso(invitation.createdAt),
    updatedAt: iso(invitation.updatedAt),
    deletedAt: iso(invitation.deletedAt),
  });

  const roleVocabulary = () => [
    ...BUILT_IN_ROLES,
    ...[...definedRoles].map(([slug, name]) => ({ slug, name })),
  ];

  const roleName = (slug: string) =>
    roleVocabulary().find((role) => role.slug === slug)?.name ?? slug;

  const newGrant = (
    organization: Organization,
    userId: string,
    role: string,
    fields: Pick<
      MembershipGrant,
      "invitedByUserId" | "acceptedAt" | "returnTo"
    >,
  ): MembershipGrant => {
    const now = new Date();
    const grant: MembershipGrant = {
      id: crypto.randomUUID(),
      organizationId: organization.id,
      userId,
      role,
      ...fields,
      createdAt: now,
      updatedAt: now,
    };
    organization.grants.push(grant);
    return grant;
  };

  const grantOf = (
    organization: Organization,
    userId: string,
    role: string,
  ) =>
    organization.grants.find((grant) =>
      grant.userId === userId && grant.role === role
    );

  const acceptGrant = (grant: MembershipGrant): MembershipGrant => {
    const now = new Date();
    grant.acceptedAt = now;
    grant.updatedAt = now;
    grant.returnTo = null;
    return grant;
  };

  const grantAccepted = (
    organization: Organization,
    userId: string,
    role: string,
    invitedByUserId: string | null,
  ): MembershipGrant => {
    const existing = grantOf(organization, userId, role);
    if (existing?.acceptedAt) return existing;
    if (existing) return acceptGrant(existing);
    return newGrant(organization, userId, role, {
      invitedByUserId,
      acceptedAt: new Date(),
      returnTo: null,
    });
  };

  const readableOrganization = (
    caller: Caller,
    organizationId: string,
  ): Organization | Response => {
    const organization = organizations.get(organizationId);
    return organization && isMember(organization.id, caller.user.id)
      ? organization
      : problem(404, ORGANIZATION_NOT_FOUND);
  };

  const managedOrganization = (
    caller: Caller,
    organizationId: string,
  ): Organization | Response => {
    const organization = organizations.get(organizationId);
    return organization &&
        holdsAny(organization.id, caller.user.id, MANAGER_ROLES)
      ? organization
      : problem(404, ORGANIZATION_NOT_FOUND);
  };

  const ownerTierRefusal = (
    organization: Organization,
    caller: Caller,
    role: string,
  ): Response | undefined =>
    role === OWNER && !holdsAny(organization.id, caller.user.id, [OWNER])
      ? problem(
        403,
        "Only an owner of this organization can offer or revoke its owner role.",
      )
      : undefined;

  const resolveReturnTo = (value: string): string | null => {
    if (value.length > RETURN_TO_MAX_LENGTH || CONTROL_CHARACTERS.test(value)) {
      return null;
    }
    if (value.startsWith("/")) {
      const path = safeReturnTo(value, "");
      return path === "" ? null : path;
    }
    try {
      const url = new URL(value);
      return (url.protocol === "https:" || url.protocol === "http:") &&
          redirectOrigins.has(url.origin)
        ? url.href
        : null;
    } catch {
      return null;
    }
  };

  const userByEmail = (email: string) =>
    [...users.values()].find((user) => user.email?.toLowerCase() === email);

  const holdsGrantOnResource = (organizationId: string) =>
    grants.filter((grant) =>
      grant.subject.type === "organization" &&
      grant.subject.id === organizationId
    );

  const organizationApi = (
    handler: (caller: Caller, request: Request, params: string[]) =>
      | Response
      | Promise<Response>,
  ): Route =>
  async (request, params) => {
    const caller = await authenticated(request);
    if (caller instanceof Response) return noStore(caller);
    return noStore(await handler(caller, request, params));
  };

  const listOrganizations = organizationApi((caller, request) =>
    Response.json(page(
      [...organizations.values()]
        .filter((organization) => isMember(organization.id, caller.user.id))
        .map(organizationJson),
      request,
    ))
  );

  const createOrganization = organizationApi(async (caller, request) => {
    const body = await jsonBody(request);
    if (!isRecord(body)) return problem(400, "Invalid organization");
    const nameRefusal = nameProblem(body.name);
    if (nameRefusal) return invalid("name", nameRefusal);
    const slugRefusal = slugProblem(body.slug);
    if (slugRefusal) return invalid("slug", slugRefusal);
    const metadataRefusal = body.metadata === undefined
      ? undefined
      : metadataProblem(body.metadata);
    if (metadataRefusal) return invalid("metadata", metadataRefusal);
    const slug = body.slug as string;
    if ([...organizations.values()].some((o) => o.slug === slug)) {
      return problem(409, "An organization with this slug already exists", {
        constraint: "organizations_tenant_slug_unique",
      });
    }
    const now = new Date();
    const organization: Organization = {
      id: crypto.randomUUID(),
      slug,
      name: body.name as string,
      metadata: (body.metadata as Record<string, unknown>) ?? {},
      createdAt: now,
      updatedAt: now,
      grants: [],
      permissions: new Map(),
    };
    organizations.set(organization.id, organization);
    grantAccepted(organization, caller.user.id, OWNER, null);
    return Response.json(organizationJson(organization), { status: 201 });
  });

  const getOrganization = organizationApi((caller, _request, [id]) => {
    const organization = readableOrganization(caller, id);
    if (organization instanceof Response) return organization;
    return Response.json(organizationJson(organization));
  });

  const patchOrganization = organizationApi(async (caller, request, [id]) => {
    const organization = managedOrganization(caller, id);
    if (organization instanceof Response) return organization;
    const body = await jsonBody(request);
    if (!isRecord(body)) return problem(400, "Invalid organization");
    if (body.name !== undefined) {
      const refusal = nameProblem(body.name);
      if (refusal) return invalid("name", refusal);
    }
    if (body.slug !== undefined) {
      const refusal = slugProblem(body.slug);
      if (refusal) return invalid("slug", refusal);
      if (
        [...organizations.values()].some((o) =>
          o.slug === body.slug && o.id !== organization.id
        )
      ) {
        return problem(409, "An organization with this slug already exists", {
          constraint: "organizations_tenant_slug_unique",
        });
      }
    }
    if (body.metadata !== undefined) {
      const refusal = metadataProblem(body.metadata);
      if (refusal) return invalid("metadata", refusal);
    }
    if (body.name !== undefined) organization.name = body.name as string;
    if (body.slug !== undefined) organization.slug = body.slug as string;
    if (body.metadata !== undefined) {
      organization.metadata = body.metadata as Record<string, unknown>;
    }
    organization.updatedAt = new Date();
    return Response.json(organizationJson(organization));
  });

  const deleteOrganization = organizationApi((caller, _request, [id]) => {
    const organization = managedOrganization(caller, id);
    if (organization instanceof Response) return organization;
    if (!holdsAny(organization.id, caller.user.id, [OWNER])) {
      return problem(403, "Only an owner of this organization can delete it.");
    }
    const held = holdsGrantOnResource(organization.id);
    if (held.length > 0) {
      const named = held.slice(0, 3).map((grant) =>
        `${grant.resource.type} ${grant.resource.id}`
      ).join(", ");
      return problem(
        409,
        `This organization still holds a role on ${named}. Revoke what it holds before deleting it.`,
      );
    }
    organizations.delete(organization.id);
    return new Response(null, { status: 204 });
  });

  const listMembers = organizationApi((caller, request, [id]) => {
    const organization = readableOrganization(caller, id);
    if (organization instanceof Response) return organization;
    return Response.json(page(
      organization.grants
        .filter((grant) => grant.acceptedAt)
        .map((grant) => {
          const { returnTo: _offerOnly, ...row } = grantJson(grant);
          const holder = users.get(grant.userId);
          return {
            ...row,
            name: holder?.name ?? holder?.username ?? "Unknown user",
            email: holder?.email ?? null,
          };
        }),
      request,
    ));
  });

  const listMemberRoles = organizationApi((caller, _request, [id]) => {
    const organization = managedOrganization(caller, id);
    if (organization instanceof Response) return organization;
    return Response.json(roleVocabulary());
  });

  const revokeMembership = organizationApi(
    (caller, _request, [id, userId, role]) => {
      const organization = managedOrganization(caller, id);
      if (organization instanceof Response) return organization;
      const refusal = ownerTierRefusal(organization, caller, role);
      if (refusal) return refusal;
      const grant = grantOf(organization, userId, role);
      if (
        role === OWNER && grant?.acceptedAt &&
        organization.grants.filter((g) => g.role === OWNER && g.acceptedAt)
            .length <= 1
      ) {
        return problem(
          409,
          "This is the organization's last owner — make someone else an owner before revoking this membership.",
        );
      }
      if (!grant) return problem(404, "Organization membership not found");
      organization.grants.splice(organization.grants.indexOf(grant), 1);
      return new Response(null, { status: 204 });
    },
  );

  const invite = organizationApi(async (caller, request, [id]) => {
    const organization = managedOrganization(caller, id);
    if (organization instanceof Response) return organization;
    const body = await jsonBody(request);
    if (!isRecord(body)) return problem(400, "Invalid invitation");
    if (typeof body.email !== "string" || !EMAIL.test(body.email)) {
      return invalid("email", "Enter a valid email address");
    }
    const slugRefusal = slugProblem(body.role);
    if (slugRefusal) return invalid("role", slugRefusal);
    if (
      body.return_to !== undefined &&
      (typeof body.return_to !== "string" || body.return_to.length === 0)
    ) {
      return invalid("return_to", "return_to must be a non-empty string");
    }
    const email = body.email.toLowerCase();
    const role = body.role as string;
    const refusal = ownerTierRefusal(organization, caller, role);
    if (refusal) return refusal;
    const returnTo = typeof body.return_to === "string"
      ? resolveReturnTo(body.return_to)
      : null;
    if (typeof body.return_to === "string" && !returnTo) {
      return invalid(
        "return_to",
        "return_to must be a path on this tenant's host or an absolute URL on the origin of a redirect URI registered on one of its live applications",
      );
    }
    const offered = [...invitations.values()].find((invitation) =>
      invitation.organizationId === organization.id &&
      invitation.email === email && invitation.role === role &&
      !invitation.acceptedAt && !invitation.deletedAt
    );
    if (offered) {
      return problem(
        409,
        `${email} was already invited to the ${role} role. Withdraw that invitation before sending another.`,
      );
    }
    const undefinedRole = roleVocabulary().some((entry) => entry.slug === role)
      ? undefined
      : invalid("role", `The role "${role}" is not defined`);
    const subject = userByEmail(email);
    if (subject) {
      if (grantOf(organization, subject.id, role)) {
        return problem(409, `That person already holds the ${role} role.`, {
          constraint: "organization_memberships_unique",
        });
      }
      if (undefinedRole) return undefinedRole;
      const membership = newGrant(organization, subject.id, role, {
        invitedByUserId: caller.user.id,
        acceptedAt: null,
        returnTo,
      });
      return Response.json(
        { status: "membership", membership: grantJson(membership) },
        { status: 201 },
      );
    }
    if (undefinedRole) return undefinedRole;
    const now = new Date();
    const invitation: Invitation = {
      id: crypto.randomUUID(),
      organizationId: organization.id,
      email,
      role,
      invitedByUserId: caller.user.id,
      expiresAt: new Date(now.getTime() + INVITATION_LIFETIME_MS),
      acceptedAt: null,
      acceptedByUserId: null,
      returnTo,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    };
    invitations.set(invitation.id, invitation);
    return Response.json(
      { status: "invitation", invitation: invitationJson(invitation) },
      { status: 201 },
    );
  });

  const listInvitations = organizationApi((caller, request, [id]) => {
    const organization = managedOrganization(caller, id);
    if (organization instanceof Response) return organization;
    const status = new URL(request.url).searchParams.get("status") ?? "";
    if (!["", "outstanding", "unaccepted"].includes(status)) {
      return invalid("status", "status must be outstanding or unaccepted");
    }
    const now = Date.now();
    return Response.json(page(
      [...invitations.values()]
        .filter((invitation) =>
          invitation.organizationId === organization.id &&
          !invitation.deletedAt &&
          (status === "" || !invitation.acceptedAt) &&
          (status !== "outstanding" || invitation.expiresAt.getTime() > now)
        )
        .map(invitationJson),
      request,
    ));
  });

  const withdrawInvitation = organizationApi(
    (caller, _request, [id, invitationId]) => {
      const organization = managedOrganization(caller, id);
      if (organization instanceof Response) return organization;
      const invitation = invitations.get(invitationId);
      if (
        !invitation || invitation.organizationId !== organization.id ||
        invitation.acceptedAt || invitation.deletedAt
      ) {
        return problem(404, "Organization invitation not found");
      }
      invitation.deletedAt = new Date();
      invitation.updatedAt = invitation.deletedAt;
      return new Response(null, { status: 204 });
    },
  );

  const pendingGrantsOf = (userId: string) =>
    [...organizations.values()].flatMap((organization) =>
      organization.grants.filter((grant) =>
        grant.userId === userId && !grant.acceptedAt
      )
    );

  const listOffers = organizationApi((caller) => {
    const { email, emailVerified = true } = caller.user;
    const unverifiedEmail = email && !emailVerified ? email : null;
    const address = email?.toLowerCase();
    const now = Date.now();
    const invited = address && !unverifiedEmail
      ? [...invitations.values()].filter((invitation) =>
        invitation.email === address && !invitation.acceptedAt &&
        !invitation.deletedAt && invitation.expiresAt.getTime() > now
      )
      : [];
    return Response.json({
      offers: [...pendingGrantsOf(caller.user.id), ...invited].flatMap(
        (offer) => {
          const organization = organizations.get(offer.organizationId);
          return organization
            ? [{
              id: offer.id,
              organizationName: organization.name,
              roleName: roleName(offer.role),
            }]
            : [];
        },
      ),
      unverifiedEmail,
    });
  });

  const acceptOffer = organizationApi((caller, _request, [offerId]) => {
    const invitation = invitations.get(offerId);
    if (invitation && !invitation.acceptedAt && !invitation.deletedAt) {
      const email = caller.user.email?.toLowerCase();
      if (
        !email || caller.user.emailVerified === false ||
        email !== invitation.email
      ) {
        return Response.json({ status: "wrong-account" });
      }
      if (invitation.expiresAt.getTime() <= Date.now()) {
        return Response.json({ status: "expired" });
      }
      const organization = organizations.get(invitation.organizationId);
      if (!organization) return Response.json({ status: "invalid" });
      invitation.acceptedAt = new Date();
      invitation.acceptedByUserId = caller.user.id;
      invitation.updatedAt = invitation.acceptedAt;
      const membership = grantAccepted(
        organization,
        caller.user.id,
        invitation.role,
        invitation.invitedByUserId,
      );
      return Response.json({
        status: "accepted",
        membership: grantJson(membership),
      });
    }
    const offered = pendingGrantsOf(caller.user.id).find((grant) =>
      grant.id === offerId
    );
    if (!offered) return Response.json({ status: "invalid" });
    return Response.json({
      status: "accepted",
      membership: grantJson(acceptGrant(offered)),
    });
  });

  const accountApi = (
    handler: (caller: Caller, request: Request, params: string[]) =>
      | Response
      | Promise<Response>,
  ): Route =>
  async (request, params) => {
    const caller = await authenticated(request, { reason: "machine_token" });
    if (caller instanceof Response) return noStore(caller);
    return noStore(await handler(caller, request, params));
  };

  const readAccount = accountApi((caller) =>
    Response.json({
      userMetadata: userMetadata.get(caller.user.id) ?? {},
    })
  );

  const patchAccount = accountApi(async (caller, request) => {
    const body = await jsonBody(request);
    if (
      !isRecord(body) || Object.keys(body).length !== 1 ||
      !("userMetadata" in body)
    ) {
      return problem(400, "Only userMetadata may be written here");
    }
    const incoming = metadataProblem(body.userMetadata);
    if (incoming) return invalid("userMetadata", incoming);
    const merged = { ...userMetadata.get(caller.user.id) ?? {} };
    for (
      const [key, value] of Object.entries(
        body.userMetadata as Record<string, unknown>,
      )
    ) {
      if (value === null) delete merged[key];
      else merged[key] = value;
    }
    const result = metadataProblem(merged);
    if (result) return invalid("userMetadata", result);
    userMetadata.set(caller.user.id, merged);
    return Response.json({ userMetadata: merged });
  });

  const currentSessionOf = (caller: Caller) => {
    const sessionId = credentials.get(caller.accessToken)?.sessionId;
    return sessionId && loginSessions.has(sessionId) ? sessionId : null;
  };

  const listSessions = accountApi((caller) => {
    const current = currentSessionOf(caller);
    return Response.json({
      sessions: [...loginSessions.values()]
        .filter((session) => session.userId === caller.user.id)
        .sort((a, b) =>
          Number(b.id === current) - Number(a.id === current) ||
          b.lastActiveAt.getTime() - a.lastActiveAt.getTime()
        )
        .map((session) => ({
          id: session.id,
          createdAt: iso(session.createdAt),
          lastActiveAt: iso(session.lastActiveAt),
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          current: session.id === current,
        })),
    });
  });

  const revokeSession = accountApi(async (caller, request, [sessionId]) => {
    if (!await isEmptyBody(request)) {
      return problem(400, "The request body must be empty");
    }
    if (sessionId === currentSessionOf(caller)) {
      return problem(
        409,
        "This is your current session — use sign out instead.",
        {
          reason: "current_session",
        },
      );
    }
    if (loginSessions.get(sessionId)?.userId !== caller.user.id) {
      return problem(404, "Session not found.");
    }
    await endSession(sessionId);
    return new Response(null, { status: 204 });
  });

  const revokeOtherSessions = accountApi(async (caller, request) => {
    if (!await isEmptyBody(request)) {
      return problem(400, "The request body must be empty");
    }
    const current = currentSessionOf(caller);
    if (!current) {
      return problem(409, "Session not found.", {
        reason: "current_session_required",
      });
    }
    const others = [...loginSessions.values()].filter((session) =>
      session.userId === caller.user.id && session.id !== current
    );
    for (const session of others) await endSession(session.id);
    return Response.json({ revoked: others.length });
  });

  const linkedAccountsOf = (userId: string) =>
    [...linkedAccounts.values()].filter((account) => account.userId === userId);

  const listLinkedAccounts = accountApi((caller) =>
    Response.json({
      identities: linkedAccountsOf(caller.user.id).map((account) => ({
        id: account.id,
        provider: account.provider,
        displayName: account.displayName,
        email: account.email,
        createdAt: iso(account.createdAt),
      })),
      hasPassword: caller.user.hasPassword ?? true,
      connectable: [],
    })
  );

  const unlinkAccount = accountApi(async (caller, request, [identityId]) => {
    if (!await isEmptyBody(request)) {
      return problem(400, "Only an empty request body is accepted");
    }
    const account = linkedAccounts.get(identityId);
    if (account?.userId !== caller.user.id) {
      return problem(404, "Connected account not found.");
    }
    const othersRemain = linkedAccountsOf(caller.user.id).length > 1;
    if (!othersRemain && !(caller.user.hasPassword ?? true)) {
      return problem(
        409,
        "This is your only way to sign in. Set a password or connect another provider before disconnecting it.",
        { reason: "last_method" },
      );
    }
    linkedAccounts.delete(account.id);
    return new Response(null, { status: 204 });
  });

  const routes: Record<string, (request: Request) => Promise<Response>> = {
    "GET /.well-known/oauth-authorization-server": (r) =>
      server.handleMetadataRequest(r),
    "GET /.well-known/openid-configuration": (r) =>
      server.handleOidcMetadataRequest(r),
    [`GET ${PATHS.authorization}`]: authorize,
    [`POST ${PATHS.token}`]: token,
    [`POST ${PATHS.revocation}`]: revocation,
    [`POST ${PATHS.introspection}`]: (r) =>
      server.handleIntrospectionRequest(r),
    [`GET ${PATHS.userinfo}`]: (r) => server.handleUserInfoRequest(r),
    [`POST ${PATHS.userinfo}`]: (r) => server.handleUserInfoRequest(r),
    [`GET ${PATHS.jwks}`]: (r) => server.handleJwksRequest(r),
    "GET /api/memberships": memberships,
    "POST /api/check": check,
    "POST /api/check/batch": checkBatch,
  };

  const segment = "([^/]+)";
  const patterns: [string, RegExp, Route][] = [
    ["GET", /^\/api\/organizations$/, listOrganizations],
    ["POST", /^\/api\/organizations$/, createOrganization],
    ["GET", /^\/api\/organizations\/offers$/, listOffers],
    [
      "POST",
      new RegExp(`^/api/organizations/offers/${segment}/accept$`),
      acceptOffer,
    ],
    ["GET", new RegExp(`^/api/organizations/${segment}$`), getOrganization],
    ["PATCH", new RegExp(`^/api/organizations/${segment}$`), patchOrganization],
    [
      "DELETE",
      new RegExp(`^/api/organizations/${segment}$`),
      deleteOrganization,
    ],
    [
      "GET",
      new RegExp(`^/api/organizations/${segment}/members$`),
      listMembers,
    ],
    [
      "GET",
      new RegExp(`^/api/organizations/${segment}/member-roles$`),
      listMemberRoles,
    ],
    [
      "DELETE",
      new RegExp(
        `^/api/organizations/${segment}/members/${segment}/${segment}$`,
      ),
      revokeMembership,
    ],
    [
      "POST",
      new RegExp(`^/api/organizations/${segment}/invitations$`),
      invite,
    ],
    [
      "GET",
      new RegExp(`^/api/organizations/${segment}/invitations$`),
      listInvitations,
    ],
    [
      "DELETE",
      new RegExp(`^/api/organizations/${segment}/invitations/${segment}$`),
      withdrawInvitation,
    ],
    ["GET", /^\/api\/account$/, readAccount],
    ["PATCH", /^\/api\/account$/, patchAccount],
    ["GET", /^\/api\/account\/sessions$/, listSessions],
    [
      "POST",
      /^\/api\/account\/sessions\/revoke-others$/,
      revokeOtherSessions,
    ],
    [
      "DELETE",
      new RegExp(`^/api/account/sessions/${segment}$`),
      revokeSession,
    ],
    ["GET", /^\/api\/account\/linked-accounts$/, listLinkedAccounts],
    [
      "DELETE",
      new RegExp(`^/api/account/linked-accounts/${segment}$`),
      unlinkAccount,
    ],
  ];

  const decoded = (segments: string[]): string[] | undefined => {
    try {
      return segments.map(decodeURIComponent);
    } catch {
      return undefined;
    }
  };

  const route = (request: Request): Promise<Response> | undefined => {
    const { pathname } = new URL(request.url);
    const exact = routes[`${request.method} ${pathname}`];
    if (exact) return exact(request);
    for (const [method, pattern, handler] of patterns) {
      if (method !== request.method) continue;
      const match = pattern.exec(pathname);
      if (!match) continue;
      const params = decoded(match.slice(1));
      return params ? handler(request, params) : undefined;
    }
    return undefined;
  };

  return {
    issuer,
    fetch: (request) =>
      route(request) ?? Promise.resolve(problem(404, "Not found")),
    addClient: async ({ secret, ...client }) => {
      await clientService.add(
        {
          grants: ["authorization_code", "refresh_token"],
          ...client,
        },
        secret,
      );
      for (const uri of client.redirectUris ?? []) {
        try {
          redirectOrigins.add(new URL(uri).origin);
        } catch {
          continue;
        }
      }
    },
    addUser: async (user) => {
      await userService.add(user, crypto.randomUUID());
      users.set(user.id, user);
      userMetadata.set(user.id, { ...user.userMetadata ?? {} });
    },
    addOrganization: (organization) => {
      if (organizations.has(organization.id)) {
        throw new Error(`Organization "${organization.id}" already exists`);
      }
      const now = new Date();
      organizations.set(organization.id, {
        id: organization.id,
        slug: organization.slug,
        name: organization.name ?? organization.slug,
        metadata: {},
        createdAt: now,
        updatedAt: now,
        grants: [],
        permissions: new Map(),
      });
    },
    addMember: (organizationId, userId, membership = {}) => {
      const organization = organizations.get(organizationId);
      if (!organization) {
        throw new Error(`Organization "${organizationId}" does not exist`);
      }
      organization.grants = organization.grants.filter((grant) =>
        grant.userId !== userId
      );
      const roles = membership.roles?.length ? membership.roles : DEFAULT_ROLES;
      for (const role of new Set(roles)) {
        newGrant(organization, userId, role, {
          invitedByUserId: null,
          acceptedAt: new Date(),
          returnTo: null,
        });
      }
      organization.permissions.set(userId, membership.permissions ?? []);
    },
    removeMember: (organizationId, userId) => {
      const organization = organizations.get(organizationId);
      if (!organization) return;
      organization.grants = organization.grants.filter((grant) =>
        grant.userId !== userId
      );
      organization.permissions.delete(userId);
    },
    defineOrganizationRole: ({ slug, name }) => {
      if (BUILT_IN_ROLES.some((role) => role.slug === slug)) {
        throw new Error(`"${slug}" is a built-in organization role`);
      }
      definedRoles.set(slug, name ?? slug);
    },
    registerResourceType: (type) => {
      resourceTypes.add(type);
    },
    grant: (grant) => {
      grants.push(grant);
    },
    linkAccount: (userId, account) => {
      if (!users.has(userId)) {
        throw new Error(`User "${userId}" does not exist`);
      }
      const linked: LinkedAccount = {
        id: crypto.randomUUID(),
        userId,
        provider: account.provider,
        displayName: account.displayName ?? account.provider,
        email: account.email ?? null,
        createdAt: new Date(),
      };
      linkedAccounts.set(linked.id, linked);
      return linked.id;
    },
    signInAs: (userId, signIn = {}) => {
      signedIn = userId ? { ...signIn, userId } : null;
    },
    issueAccessToken: async (request) => {
      const client = await clientService.get(request.clientId);
      const user = users.get(request.userId);
      if (!client) {
        throw new Error(`Client "${request.clientId}" does not exist`);
      }
      if (!user) throw new Error(`User "${request.userId}" does not exist`);
      const scope = new BasicScope(request.scope ?? "openid");
      return await withIssuance(
        user.id,
        {
          organizationId: request.organizationId ?? soleOrganizationOf(user.id),
        },
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
