/**
 * The authorization a verified credential carries, as one checkable object.
 *
 * {@link Authorization} is built from a token's verified claims (an RFC 9068
 * JWT's payload, an introspection response, or an id_token's claims) and
 * answers the checks an application makes: `scope` for what the **client**
 * was delegated, `permissions`/`roles` for what the **person** holds, and the
 * active organization context. The same object is exposed on the resource
 * server's authenticated context, and can be built anywhere claims are held
 * (a BFF session's user, a browser client's session) so every surface checks
 * authorization the same way.
 *
 * Predicates never throw — they return booleans, so conditional rendering and
 * branching never need try/catch. Enforcement (turning a failed check into a
 * response) belongs to the resource server and its middleware.
 *
 * @module
 */

import type { AbstractScope } from "./scope.ts";

/**
 * The active organization a credential was issued in: the one organization
 * whose roles and permissions the credential carries. Absent (`null` on
 * {@link Authorization.organization}) when the subject acts outside any
 * organization; anything about an organization the credential does not name
 * is answered by a check endpoint, never by the token.
 */
export interface OrganizationContext {
  /** The organization's id (the `org_id` claim). */
  id: string;
  /** The organization's stable handle (the `org_slug` claim), when issued. */
  slug?: string;
  /** Roles the subject holds in this organization (the `org_roles` claim). */
  roles: ReadonlySet<string>;
}

/**
 * Conditions for {@link Authorization.unmet} and the resource servers'
 * `require()` middleware. Every named condition must hold (AND semantics),
 * and an array value means **all of** its entries — any-of checks are
 * deliberately not expressible here; branch on the {@link Authorization}
 * object in a handler instead, where the semantics stay visible.
 */
export interface RequireConditions {
  /**
   * Scope the client must have been granted. A space-delimited string or an
   * array both mean all of the named scopes.
   */
  scope?: string | string[];
  /** Permission(s) the subject must hold ({@link Authorization.can}). */
  permission?: string | string[];
  /** Tenant-wide role(s) the subject must hold ({@link Authorization.hasRole}). */
  role?: string | string[];
  /**
   * Role(s) the subject must hold in the active organization
   * ({@link Authorization.hasOrgRole}).
   */
  orgRole?: string | string[];
  /**
   * Organization context required: `true` for "any active organization", or
   * an id/slug the active organization must match
   * ({@link Authorization.inOrganization}).
   */
  organization?: true | string;
}

/**
 * The first condition of a {@link RequireConditions} the authorization does
 * not satisfy — `kind` names which check failed and `required` what it asked
 * for. Scope conditions are not reported here: the resource server enforces
 * them through its scope assertion so the RFC 6750 `insufficient_scope`
 * challenge stays identical to `requireScope`'s.
 */
export interface AuthorizationFailure {
  /** Which check failed. */
  kind: "organization" | "role" | "orgRole" | "permission";
  /** The condition value that was not met. */
  required: string | true;
}

/** The parts an {@link Authorization} is constructed from. */
export interface AuthorizationInit {
  /** The scope granted to the client, when known. */
  scope?: AbstractScope | null;
  /** Tenant-wide role slugs the subject holds. */
  roles?: Iterable<string>;
  /** Permissions the subject holds (tenant-level plus the active organization's). */
  permissions?: Iterable<string>;
  /** The active organization context, when the credential carries one. */
  organization?: OrganizationContext | null;
}

/**
 * Checkable authorization derived from a credential's verified claims.
 *
 * Build one with {@link authorizationFromClaims}, or construct directly when
 * your claims use different names. A machine token (no resource owner) yields
 * empty roles/permissions and no organization — only its scope answers.
 *
 * @example
 * ```ts
 * import { authorizationFromClaims } from "@udibo/oauth2/server";
 *
 * const authorization = authorizationFromClaims({
 *   roles: ["editor"],
 *   permissions: ["posts:write"],
 *   org_id: "org-1",
 *   org_slug: "acme",
 *   org_roles: ["admin"],
 * });
 * authorization.can("posts:write"); // true
 * authorization.inOrganization("acme"); // true
 * authorization.hasRole("admin"); // false — that role is org-scoped
 * ```
 */
export class Authorization {
  /** The scope granted to the client, or `null` when unknown. */
  readonly scope: AbstractScope | null;
  /** Tenant-wide role slugs the subject holds. */
  readonly roles: ReadonlySet<string>;
  /** Permissions the subject holds in the credential's scope of issue. */
  readonly permissions: ReadonlySet<string>;
  /** The active organization, or `null` when the credential names none. */
  readonly organization: OrganizationContext | null;

  /** Builds an authorization from already-parsed parts. */
  constructor(init: AuthorizationInit = {}) {
    this.scope = init.scope ?? null;
    this.roles = new Set(init.roles ?? []);
    this.permissions = new Set(init.permissions ?? []);
    this.organization = init.organization ?? null;
  }

  /**
   * Whether the client was granted `scope` — the delegation check, distinct
   * from what the person may do. A space-delimited string means all of the
   * named scopes. `false` when the granted scope is unknown.
   */
  hasScope(scope: string): boolean {
    return this.scope?.has(scope) ?? false;
  }

  /**
   * Whether the subject holds `permission` — the recommended check: a
   * permission is the contract, role names are presentation.
   */
  can(permission: string): boolean {
    return this.permissions.has(permission);
  }

  /** Whether the subject holds the tenant-wide role `role`. */
  hasRole(role: string): boolean {
    return this.roles.has(role);
  }

  /** Whether the subject holds `role` in the active organization. */
  hasOrgRole(role: string): boolean {
    return this.organization?.roles.has(role) ?? false;
  }

  /**
   * Whether the credential was issued in an active organization — any one
   * when called without an argument, or the one whose id or slug matches
   * `idOrSlug`.
   */
  inOrganization(idOrSlug?: string): boolean {
    if (!this.organization) return false;
    if (idOrSlug === undefined) return true;
    return this.organization.id === idOrSlug ||
      this.organization.slug === idOrSlug;
  }

  /**
   * The first non-scope condition this authorization does not satisfy, or
   * `undefined` when every one holds. Scope conditions are ignored here —
   * the resource server asserts them separately so the RFC 6750 challenge
   * semantics stay intact. Checked in order: organization, role, orgRole,
   * permission.
   */
  unmet(conditions: RequireConditions): AuthorizationFailure | undefined {
    if (
      conditions.organization !== undefined &&
      !this.inOrganization(
        conditions.organization === true ? undefined : conditions.organization,
      )
    ) {
      return { kind: "organization", required: conditions.organization };
    }
    for (const role of listOf(conditions.role)) {
      if (!this.hasRole(role)) return { kind: "role", required: role };
    }
    for (const role of listOf(conditions.orgRole)) {
      if (!this.hasOrgRole(role)) return { kind: "orgRole", required: role };
    }
    for (const permission of listOf(conditions.permission)) {
      if (!this.can(permission)) {
        return { kind: "permission", required: permission };
      }
    }
    return undefined;
  }
}

function listOf(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return typeof value === "string" ? [value] : value;
}

function stringsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Build an {@link Authorization} from a credential's verified claims — an
 * RFC 9068 access token's payload, an RFC 7662 introspection response, or an
 * id_token's claims. Reads the `roles`, `permissions`, `org_id`, `org_slug`,
 * and `org_roles` claims; anything malformed is treated as absent rather
 * than thrown on, since claim shapes vary by issuer. There is no active
 * organization unless `org_id` is a string — its presence is the whole
 * question.
 *
 * Verify claims before building from them: this function trusts its input.
 * `scope` is passed separately because access-token scope arrives as the
 * token's own granted scope object, and id_token claims carry none.
 */
export function authorizationFromClaims(
  claims: Record<string, unknown> | null | undefined,
  scope?: AbstractScope | null,
): Authorization {
  const orgId = claims?.org_id;
  const orgSlug = claims?.org_slug;
  return new Authorization({
    scope,
    roles: stringsOf(claims?.roles),
    permissions: stringsOf(claims?.permissions),
    organization: typeof orgId === "string"
      ? {
        id: orgId,
        slug: typeof orgSlug === "string" ? orgSlug : undefined,
        roles: new Set(stringsOf(claims?.org_roles)),
      }
      : null,
  });
}
