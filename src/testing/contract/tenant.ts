/**
 * Contract test suite for what a Udibo Identity tenant answers an application
 * about its signed-in people: what introspection reports, what
 * `GET /api/memberships` lists, what `POST /api/check` and
 * `POST /api/check/batch` answer, the organization API under
 * `/api/organizations`, and the account API under `/api/account`.
 *
 * It runs against `createFakeTenant` from `@udibo/oauth2/testing` and against the
 * real identity service in Udibo's own repository, so the fake an app tests
 * with answers the way the tenant it ships against does. Run it against
 * another stand-in to hold it to the same answers.
 *
 * @example
 * ```ts
 * import {
 *   runTenantContractTests,
 *   type TenantContractFixture,
 * } from "@udibo/oauth2/testing/contract";
 *
 * declare function startSeededTenant(): Promise<TenantContractFixture>;
 *
 * runTenantContractTests({ setup: startSeededTenant });
 * ```
 *
 * @module
 */

import {
  assert,
  assertEquals,
  assertFalse,
  assertStringIncludes,
} from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import { encodeBasicAuth } from "../../utils/basic-auth.ts";

/** A token response from a completed sign-in. */
export interface TenantContractTokens {
  /** The access token the sign-in issued. */
  access_token: string;
  /** The refresh token the sign-in issued. */
  refresh_token: string;
}

/** A tenant under test, and how the suite seeds it. */
export interface TenantContractFixture {
  /** The tenant's origin; its RFC 8414 metadata is served beneath it. */
  issuer: string;
  /**
   * A confidential first-party client the suite signs in with, introspects
   * with, refreshes with and revokes with. It must be allowed the
   * `refresh_token` grant.
   */
  client: { id: string; secret: string };
  /**
   * How the suite reaches the tenant. Defaults to the global `fetch`; supply
   * one when the tenant's host resolves only through a proxy.
   */
  fetch?: typeof fetch;
  /**
   * Adds a person holding `permissions` tenant-wide, and returns their id. The
   * organization and account checks pass a `profile`; the others do not.
   */
  addUser(
    permissions: string[],
    profile?: TenantContractProfile,
  ): Promise<string>;
  /**
   * Links an external sign-in account to a person and returns the linked
   * account's id.
   */
  linkAccount(
    userId: string,
    account: { provider: string; email: string | null },
  ): Promise<string>;
  /** Adds an organization and returns its id. */
  addOrganization(): Promise<string>;
  /**
   * Makes a person a `member` of an organization, holding `permissions`
   * inside it.
   */
  addMember(
    organizationId: string,
    userId: string,
    permissions: string[],
  ): Promise<void>;
  /** Ends a membership. */
  removeMember(organizationId: string, userId: string): Promise<void>;
  /**
   * Grants `permissions` on one instance of a resource type to a person, or
   * to every member of an organization. Registers the type if it is new.
   */
  grant(grant: {
    resource: { type: string; id: string };
    subject: { type: "user" | "organization"; id: string };
    permissions: string[];
  }): Promise<void>;
  /**
   * Signs the person in through the authorization-code flow and returns the
   * tokens it issued. With an organization named, the credential is issued in
   * it; with none, the sign-in picks nothing, leaving the tenant to decide.
   * Each sign-in comes from a new browser and so starts a login session of its
   * own, unless `options.sameBrowser` says otherwise.
   */
  signIn(
    userId: string,
    organizationId?: string,
    options?: TenantContractSignInOptions,
  ): Promise<TenantContractTokens>;
  /** Releases anything `setup` allocated. */
  cleanup?(): Promise<void> | void;
}

/** How `TenantContractFixture.signIn` signs a person in. */
export interface TenantContractSignInOptions {
  /**
   * Sign in from the browser this person's previous sign-in used, so the
   * tenant continues that login session instead of starting another. The
   * suite asks for it only straight after that previous sign-in.
   */
  sameBrowser?: boolean;
}

/** Who a person added with `TenantContractFixture.addUser` is. */
export interface TenantContractProfile {
  /**
   * The address the person holds. When it is omitted, the fixture may give them
   * any address or none.
   */
  email?: string;
  /** Whether that address is verified. Defaults to `true`. */
  emailVerified?: boolean;
  /**
   * Whether the person has a password. Defaults to `true`. With `false`, the
   * fixture must still be able to sign them in, the way a tenant signs such a
   * person in through a linked account.
   */
  password?: boolean;
}

/** Options for {@link runTenantContractTests}. */
export interface TenantContractOptions {
  /** Overrides the top-level `describe` name. */
  describeName?: string;
  /** Builds the tenant once for the whole suite. */
  setup(): Promise<TenantContractFixture> | TenantContractFixture;
}

interface Introspection {
  active?: boolean;
  sub?: string;
  permissions?: string[];
  org_id?: string;
}

/**
 * Registers the tenant contract suite. The permissions and resource type it
 * seeds are namespaced `contract`, so a tenant shared with other suites is
 * safe as long as nothing else uses that namespace.
 */
export function runTenantContractTests(options: TenantContractOptions): void {
  describe(options.describeName ?? "Udibo Identity tenant contract", () => {
    let tenant: TenantContractFixture;
    let metadata: {
      token_endpoint: string;
      introspection_endpoint: string;
      revocation_endpoint: string;
    };
    let send: typeof fetch;
    const people: Record<"member" | "outsider" | "leaver" | "solo", string> = {
      member: "",
      outsider: "",
      leaver: "",
      solo: "",
    };
    const organizations = { home: "", other: "", unjoined: "" };

    beforeAll(async () => {
      tenant = await options.setup();
      send = tenant.fetch ?? fetch;
      const response = await send(
        new URL("/.well-known/oauth-authorization-server", tenant.issuer),
      );
      metadata = await response.json();
      people.member = await tenant.addUser(["contract:tenant"]);
      people.outsider = await tenant.addUser([]);
      people.leaver = await tenant.addUser([]);
      people.solo = await tenant.addUser([]);
      organizations.home = await tenant.addOrganization();
      organizations.other = await tenant.addOrganization();
      organizations.unjoined = await tenant.addOrganization();
      await tenant.addMember(organizations.home, people.member, [
        "contract:home",
      ]);
      await tenant.addMember(organizations.other, people.member, [
        "contract:other",
      ]);
      await tenant.addMember(organizations.home, people.outsider, []);
      await tenant.addMember(organizations.home, people.leaver, [
        "contract:home",
      ]);
      await tenant.addMember(organizations.other, people.solo, [
        "contract:other",
      ]);
      await tenant.grant({
        resource: { type: "contract_document", id: "direct" },
        subject: { type: "user", id: people.outsider },
        permissions: ["contract:read"],
      });
      await tenant.grant({
        resource: { type: "contract_document", id: "shared" },
        subject: { type: "organization", id: organizations.home },
        permissions: ["contract:write"],
      });
    });

    afterAll(async () => {
      await tenant?.cleanup?.();
    });

    const clientAuth = () =>
      encodeBasicAuth(tenant.client.id, tenant.client.secret);

    async function introspect(accessToken: string): Promise<Introspection> {
      const response = await send(metadata.introspection_endpoint, {
        method: "POST",
        headers: { authorization: clientAuth() },
        body: new URLSearchParams({ token: accessToken }),
      });
      assertEquals(response.status, 200);
      return await response.json();
    }

    async function ask(
      accessToken: string,
      path: string,
      body: unknown,
    ): Promise<{ status: number; body: Record<string, unknown> }> {
      const response = await send(new URL(path, tenant.issuer), {
        method: "POST",
        headers: {
          authorization: `Bearer ${accessToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      });
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : {} };
    }

    const sorted = (values: string[] | undefined) => [...values ?? []].sort();

    describe("introspection", () => {
      it("reports tenant-wide permissions and no organization for a sign-in that picked none", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const claims = await introspect(access_token);
        assertEquals(claims.active, true);
        assertEquals(claims.sub, people.member);
        assertEquals(sorted(claims.permissions), ["contract:tenant"]);
        assertFalse(claims.org_id, "a sign-in with no organization names none");
      });

      it("picks a person's only organization when the sign-in names none", async () => {
        const { access_token } = await tenant.signIn(people.solo);
        const claims = await introspect(access_token);
        assertEquals(claims.org_id, organizations.other);
        assertEquals(sorted(claims.permissions), ["contract:other"]);
      });

      it("adds the picked organization and its permissions, and no other's", async () => {
        const { access_token } = await tenant.signIn(
          people.member,
          organizations.home,
        );
        const claims = await introspect(access_token);
        assertEquals(claims.org_id, organizations.home);
        assertEquals(sorted(claims.permissions), [
          "contract:home",
          "contract:tenant",
        ]);
      });

      it("keeps a refreshed credential in the organization it was issued for", async () => {
        const issued = await tenant.signIn(people.member, organizations.other);
        await tenant.signIn(people.member, organizations.home);
        const response = await send(metadata.token_endpoint, {
          method: "POST",
          headers: { authorization: clientAuth() },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: issued.refresh_token,
          }),
        });
        assertEquals(response.status, 200);
        const refreshed = await response.json();
        const claims = await introspect(refreshed.access_token);
        assertEquals(claims.org_id, organizations.other);
      });

      it("stops answering for an organization once the membership ends", async () => {
        const { access_token } = await tenant.signIn(
          people.leaver,
          organizations.home,
        );
        await tenant.removeMember(organizations.home, people.leaver);
        const claims = await introspect(access_token);
        assertFalse(claims.org_id);
        assertEquals(sorted(claims.permissions), []);
      });
    });

    describe("GET /api/memberships", () => {
      it("lists the organizations the caller belongs to, and no others", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const response = await send(
          new URL("/api/memberships", tenant.issuer),
          { headers: { authorization: `Bearer ${access_token}` } },
        );
        assertEquals(response.status, 200);
        const body = await response.json() as {
          memberships: {
            org_id: string;
            org_slug: string;
            name: string;
            roles: string[];
          }[];
          cursor: string | null;
        };
        assertEquals(
          body.memberships.map((membership) => membership.org_id).sort(),
          [organizations.home, organizations.other].sort(),
        );
        for (const membership of body.memberships) {
          assertEquals(membership.roles, ["member"]);
          assert(membership.org_slug, "every membership names its slug");
          assert(membership.name, "every membership names its organization");
        }
        assertEquals(body.cursor, null);
      });

      it("refuses a caller with no bearer token", async () => {
        const response = await send(new URL("/api/memberships", tenant.issuer));
        await response.body?.cancel();
        assertEquals(response.status, 401);
      });
    });

    describe("POST /api/check", () => {
      it("answers the credential's own organization when no resource is named", async () => {
        const { access_token } = await tenant.signIn(
          people.member,
          organizations.home,
        );
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:home", "contract:other", "contract:tenant"],
        });
        assertEquals(answer.status, 200);
        assertEquals(answer.body, {
          subject: people.member,
          resource: { type: "organization", id: organizations.home },
          results: {
            "contract:home": true,
            "contract:other": false,
            "contract:tenant": true,
          },
        });
      });

      it("answers tenant scope alone, naming no resource, for a credential with no organization", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:home", "contract:tenant"],
        });
        assertEquals(answer.body, {
          subject: people.member,
          resource: null,
          results: { "contract:home": false, "contract:tenant": true },
        });
      });

      it("answers another organization the caller belongs to when it is named", async () => {
        const { access_token } = await tenant.signIn(
          people.member,
          organizations.home,
        );
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:other"],
          resource: { type: "organization", id: organizations.other },
        });
        assertEquals(answer.status, 200);
        assertEquals(answer.body.results, { "contract:other": true });
      });

      it("answers an organization the caller does not belong to from tenant-wide permissions alone", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:other", "contract:tenant"],
          resource: { type: "organization", id: organizations.unjoined },
        });
        assertEquals(answer.status, 200);
        assertEquals(answer.body.results, {
          "contract:other": false,
          "contract:tenant": true,
        });
      });

      it("answers an organization that does not exist as not found", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:tenant"],
          resource: { type: "organization", id: crypto.randomUUID() },
        });
        assertEquals(answer.status, 404);
      });

      it("answers a resource from a grant to the person and from one to their organization", async () => {
        const { access_token } = await tenant.signIn(people.outsider);
        const direct = await ask(access_token, "/api/check", {
          permissions: ["contract:read", "contract:write"],
          resource: { type: "contract_document", id: "direct" },
        });
        assertEquals(direct.status, 200);
        assertEquals(direct.body.results, {
          "contract:read": true,
          "contract:write": false,
        });
        const shared = await ask(access_token, "/api/check", {
          permissions: ["contract:write"],
          resource: { type: "contract_document", id: "shared" },
        });
        assertEquals(shared.body.results, { "contract:write": true });
      });

      it("leaves organization permissions out of a resource answer", async () => {
        const { access_token } = await tenant.signIn(
          people.member,
          organizations.home,
        );
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:home", "contract:tenant"],
          resource: { type: "contract_document", id: "direct" },
        });
        assertEquals(answer.body.results, {
          "contract:home": false,
          "contract:tenant": true,
        });
      });

      it("refuses a resource type the tenant has not registered", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:read"],
          resource: { type: "contract_unregistered", id: "x" },
        });
        assertEquals(answer.status, 400);
      });

      it("refuses a caller with no bearer token", async () => {
        const response = await send(new URL("/api/check", tenant.issuer), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ permissions: ["contract:tenant"] }),
        });
        await response.body?.cancel();
        assertEquals(response.status, 401);
      });
    });

    describe("POST /api/check/batch", () => {
      it("answers each candidate id as /api/check would", async () => {
        const { access_token } = await tenant.signIn(people.outsider);
        const answer = await ask(access_token, "/api/check/batch", {
          permissions: ["contract:read"],
          resource: { type: "contract_document", ids: ["direct", "unseen"] },
        });
        assertEquals(answer.status, 200);
        assertEquals(answer.body, {
          subject: people.outsider,
          resource: { type: "contract_document" },
          results: {
            direct: { "contract:read": true },
            unseen: { "contract:read": false },
          },
        });
      });

      it("refuses more than a hundred candidates", async () => {
        const { access_token } = await tenant.signIn(people.outsider);
        const answer = await ask(access_token, "/api/check/batch", {
          permissions: ["contract:read"],
          resource: {
            type: "contract_document",
            ids: Array.from({ length: 101 }, (_, i) => `id-${i}`),
          },
        });
        assert(answer.status === 400, `answered ${answer.status}`);
      });
    });

    interface Reply<T> {
      status: number;
      headers: Headers;
      body: T;
    }

    async function call<T = Record<string, unknown>>(
      accessToken: string | null,
      method: string,
      path: string,
      body?: unknown,
    ): Promise<Reply<T>> {
      const headers: Record<string, string> = accessToken
        ? { authorization: `Bearer ${accessToken}` }
        : {};
      if (body !== undefined) headers["content-type"] = "application/json";
      const response = await send(new URL(path, tenant.issuer), {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const text = await response.text();
      return {
        status: response.status,
        headers: response.headers,
        body: (text ? JSON.parse(text) : null) as T,
      };
    }

    const newEmail = () => `contract-${crypto.randomUUID()}@example.com`;
    const newSlug = () => `contract-${crypto.randomUUID().slice(0, 13)}`;

    interface Person {
      id: string;
      email: string;
      token: string;
    }

    async function person(
      profile: TenantContractProfile = {},
    ): Promise<Person> {
      const email = profile.email ?? newEmail();
      const id = await tenant.addUser([], { ...profile, email });
      const { access_token } = await tenant.signIn(id);
      return { id, email, token: access_token };
    }

    interface Organization {
      id: string;
      slug: string;
      name: string;
    }

    interface Member {
      id: string;
      userId: string;
      role: string;
      name: string;
      email: string | null;
      acceptedAt: string | null;
    }

    interface Page<T> {
      data: T[];
      cursors: { next: string | null; prev: string | null };
      hasMore: boolean;
    }

    interface Offers {
      offers: { id: string; organizationName: string; roleName: string }[];
      unverifiedEmail: string | null;
    }

    type InviteOutcome =
      | { status: "membership"; membership: Member }
      | {
        status: "invitation";
        invitation: { id: string; email: string; role: string };
      };

    interface AcceptOutcome {
      status: string;
      membership?: { organizationId: string; role: string; userId: string };
    }

    interface Membership {
      org_id: string;
      org_slug: string;
      name: string;
      roles: string[];
    }

    async function membershipsOf(accessToken: string): Promise<Membership[]> {
      const reply = await call<{ memberships: Membership[] }>(
        accessToken,
        "GET",
        "/api/memberships",
      );
      assertEquals(reply.status, 200);
      return reply.body.memberships;
    }

    async function createOrganization(
      accessToken: string,
    ): Promise<Organization> {
      const slug = newSlug();
      const reply = await call<Organization>(
        accessToken,
        "POST",
        "/api/organizations",
        { name: `Contract ${slug}`, slug },
      );
      assertEquals(reply.status, 201, JSON.stringify(reply.body));
      return reply.body;
    }

    async function invite(
      accessToken: string,
      organizationId: string,
      email: string,
      role: string,
    ): Promise<Reply<InviteOutcome>> {
      return await call<InviteOutcome>(
        accessToken,
        "POST",
        `/api/organizations/${organizationId}/invitations`,
        { email, role },
      );
    }

    async function accept(
      accessToken: string,
      offerId: string,
    ): Promise<AcceptOutcome> {
      const reply = await call<AcceptOutcome>(
        accessToken,
        "POST",
        `/api/organizations/offers/${offerId}/accept`,
      );
      assertEquals(reply.status, 200, JSON.stringify(reply.body));
      return reply.body;
    }

    async function seat(
      managerToken: string,
      organizationId: string,
      invitee: Person,
      role: string,
    ): Promise<void> {
      const offered = await invite(
        managerToken,
        organizationId,
        invitee.email,
        role,
      );
      assertEquals(offered.status, 201, JSON.stringify(offered.body));
      assert(offered.body.status === "membership", offered.body.status);
      const accepted = await accept(invitee.token, offered.body.membership.id);
      assertEquals(accepted.status, "accepted");
    }

    async function membersOf(
      accessToken: string,
      organizationId: string,
    ): Promise<Reply<Page<Member>>> {
      return await call<Page<Member>>(
        accessToken,
        "GET",
        `/api/organizations/${organizationId}/members`,
      );
    }

    describe("the organization API", () => {
      const seats = {} as Record<
        "owner" | "admin" | "member" | "outsider" | "rival" | "rivalMember",
        Person
      >;
      let organization: Organization;
      let rival: Organization;
      let rivalInvitationId: string;

      beforeAll(async () => {
        seats.owner = await person();
        seats.admin = await person();
        seats.member = await person();
        seats.outsider = await person();
        seats.rival = await person();
        seats.rivalMember = await person();
        organization = await createOrganization(seats.owner.token);
        await seat(seats.owner.token, organization.id, seats.admin, "admin");
        await seat(seats.owner.token, organization.id, seats.member, "member");
        rival = await createOrganization(seats.rival.token);
        await seat(seats.rival.token, rival.id, seats.rivalMember, "member");
        const rivalOffer = await invite(
          seats.rival.token,
          rival.id,
          newEmail(),
          "member",
        );
        assert(rivalOffer.body.status === "invitation", rivalOffer.body.status);
        rivalInvitationId = rivalOffer.body.invitation.id;
      });

      async function invitationIdsOf(
        accessToken: string,
        organizationId: string,
      ): Promise<string[]> {
        const listed = await call<Page<{ id: string }>>(
          accessToken,
          "GET",
          `/api/organizations/${organizationId}/invitations`,
        );
        assertEquals(listed.status, 200);
        return listed.body.data.map((entry) => entry.id);
      }

      it("creates an organization its creator owns", async () => {
        const creator = await person();
        const slug = newSlug();
        const created = await call<Organization>(
          creator.token,
          "POST",
          "/api/organizations",
          { name: "Contract Created", slug },
        );
        assertEquals(created.status, 201);
        assertEquals(created.body.slug, slug);
        assertEquals(created.body.name, "Contract Created");
        const listed = await call<Page<Organization>>(
          creator.token,
          "GET",
          "/api/organizations",
        );
        assertEquals(listed.status, 200);
        assertEquals(
          listed.body.data.map((entry) => entry.id),
          [created.body.id],
        );
        assertEquals(await membershipsOf(creator.token), [{
          org_id: created.body.id,
          org_slug: slug,
          name: "Contract Created",
          roles: ["owner"],
        }]);
      });

      it("refuses a slug another organization holds", async () => {
        const reply = await call(
          seats.outsider.token,
          "POST",
          "/api/organizations",
          { name: "Contract Taken", slug: organization.slug },
        );
        assertEquals(reply.status, 409);
      });

      it("refuses a slug that is not lowercase letters, numbers and single hyphens", async () => {
        const reply = await call(
          seats.outsider.token,
          "POST",
          "/api/organizations",
          { name: "Contract Shouting", slug: "Contract--Shouting" },
        );
        assertEquals(reply.status, 400);
      });

      it("lets a member of any tier read the organization and its members, and no cache keep them", async () => {
        const read = await call<Organization>(
          seats.member.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        assertEquals(read.status, 200);
        assertEquals(read.body.id, organization.id);
        assertEquals(read.body.slug, organization.slug);
        assertStringIncludes(
          read.headers.get("cache-control") ?? "",
          "no-store",
        );
        const members = await membersOf(seats.member.token, organization.id);
        assertEquals(members.status, 200);
        assertStringIncludes(
          members.headers.get("cache-control") ?? "",
          "no-store",
        );
        assertEquals(
          members.body.data.map((row) => `${row.userId}:${row.role}`).sort(),
          [
            `${seats.admin.id}:admin`,
            `${seats.member.id}:member`,
            `${seats.owner.id}:owner`,
          ].sort(),
        );
        assertFalse(members.body.hasMore);
        for (const row of members.body.data) {
          assert(row.id, "every member row names its grant");
          assert(row.name, "every member row names its person");
          assert(row.acceptedAt, "a member row is an accepted grant");
        }
        assertEquals(
          members.body.data.find((row) => row.userId === seats.member.id)
            ?.email,
          seats.member.email,
        );
      });

      it("answers a non-member, an unknown id and a malformed id with the same 404", async () => {
        const outsider = await call<{ detail?: string }>(
          seats.outsider.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        const unknown = await call<{ detail?: string }>(
          seats.owner.token,
          "GET",
          `/api/organizations/${crypto.randomUUID()}`,
        );
        const malformed = await call<{ detail?: string }>(
          seats.owner.token,
          "GET",
          "/api/organizations/not-an-organization",
        );
        assertEquals(
          [outsider.status, unknown.status, malformed.status],
          [404, 404, 404],
        );
        assertEquals(outsider.body.detail, unknown.body.detail);
        assertEquals(unknown.body.detail, malformed.body.detail);
        const members = await membersOf(seats.outsider.token, organization.id);
        assertEquals(members.status, 404);
      });

      it("lets an owner or admin rename the organization and a plain member not", async () => {
        const renamed = await call<Organization>(
          seats.admin.token,
          "PATCH",
          `/api/organizations/${organization.id}`,
          { name: "Contract Renamed" },
        );
        assertEquals(renamed.status, 200);
        assertEquals(renamed.body.name, "Contract Renamed");
        assertEquals(renamed.body.slug, organization.slug);
        for (const caller of [seats.member, seats.outsider]) {
          const refused = await call(
            caller.token,
            "PATCH",
            `/api/organizations/${organization.id}`,
            { name: "Contract Hijacked" },
          );
          assertEquals(refused.status, 404);
        }
      });

      it("lists the membership tiers an invitation may offer, to a manager only", async () => {
        const roles = await call<{ slug: string; name: string }[]>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/member-roles`,
        );
        assertEquals(roles.status, 200);
        assertEquals(roles.body.slice(0, 3), [
          { slug: "owner", name: "Owner" },
          { slug: "admin", name: "Admin" },
          { slug: "member", name: "Member" },
        ]);
        const refused = await call(
          seats.member.token,
          "GET",
          `/api/organizations/${organization.id}/member-roles`,
        );
        assertEquals(refused.status, 404);
      });

      it("offers an existing person a pending membership that confers nothing until they accept it", async () => {
        const invitee = await person();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          invitee.email,
          "member",
        );
        assertEquals(offered.status, 201);
        assert(offered.body.status === "membership", offered.body.status);
        assertEquals(offered.body.membership.role, "member");
        assertEquals(offered.body.membership.acceptedAt, null);
        assertEquals(await membershipsOf(invitee.token), []);
        const before = await membersOf(seats.admin.token, organization.id);
        assertFalse(
          before.body.data.some((row) => row.userId === invitee.id),
          "a pending grant is not a member",
        );

        const waiting = await call<Offers>(
          invitee.token,
          "GET",
          "/api/organizations/offers",
        );
        assertEquals(waiting.status, 200);
        const current = await call<Organization>(
          seats.owner.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        assertEquals(waiting.body, {
          offers: [{
            id: offered.body.membership.id,
            organizationName: current.body.name,
            roleName: "Member",
          }],
          unverifiedEmail: null,
        });

        const accepted = await accept(
          invitee.token,
          offered.body.membership.id,
        );
        assertEquals(accepted.status, "accepted");
        assertEquals(accepted.membership?.organizationId, organization.id);
        assertEquals(accepted.membership?.role, "member");
        assertEquals(
          (await membershipsOf(invitee.token)).map((entry) => entry.roles),
          [["member"]],
        );
        const after = await membersOf(seats.admin.token, organization.id);
        assert(after.body.data.some((row) => row.userId === invitee.id));
      });

      it("answers an offer the caller cannot accept as invalid, and leaves it unspent", async () => {
        const invitee = await person();
        const offered = await invite(
          seats.owner.token,
          organization.id,
          invitee.email,
          "member",
        );
        assert(offered.body.status === "membership", offered.body.status);
        const offerId = offered.body.membership.id;
        assertEquals(
          (await accept(seats.outsider.token, offerId)).status,
          "invalid",
        );
        assertEquals(
          (await accept(seats.outsider.token, "not-an-offer")).status,
          "invalid",
        );
        assertEquals((await accept(invitee.token, offerId)).status, "accepted");
      });

      it("refuses a second offer of a role an address already holds or was offered", async () => {
        const stranger = newEmail();
        const first = await invite(
          seats.admin.token,
          organization.id,
          stranger,
          "member",
        );
        assertEquals(first.status, 201);
        const again = await invite(
          seats.admin.token,
          organization.id,
          stranger,
          "member",
        );
        assertEquals(again.status, 409);
        const held = await invite(
          seats.admin.token,
          organization.id,
          seats.member.email,
          "member",
        );
        assertEquals(held.status, 409);
      });

      it("keeps the owner tier to owners", async () => {
        const offered = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "owner",
        );
        assertEquals(offered.status, 403);
        const revoked = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${seats.owner.id}/owner`,
        );
        assertEquals(revoked.status, 403);
      });

      it("refuses a plain member every manager action with the 404 a stranger gets, and changes nothing", async () => {
        const pending = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "member",
        );
        assert(pending.body.status === "invitation", pending.body.status);
        const pendingId = pending.body.invitation.id;
        const base = `/api/organizations/${organization.id}`;
        const actions: [string, string][] = [
          ["DELETE", `${base}/members/${seats.admin.id}/admin`],
          ["DELETE", `${base}/invitations/${pendingId}`],
          ["GET", `${base}/invitations`],
        ];
        for (const [method, path] of actions) {
          const byMember = await call<{ detail?: string }>(
            seats.member.token,
            method,
            path,
          );
          const byStranger = await call<{ detail?: string }>(
            seats.outsider.token,
            method,
            path,
          );
          assertEquals(
            [byMember.status, byStranger.status],
            [404, 404],
            `${method} ${path}`,
          );
          assertEquals(byMember.body.detail, byStranger.body.detail);
        }
        const members = await membersOf(seats.owner.token, organization.id);
        assert(
          members.body.data.some((row) =>
            row.userId === seats.admin.id && row.role === "admin"
          ),
          "a plain member revoked a manager's tier",
        );
        assert(
          (await invitationIdsOf(seats.admin.token, organization.id)).includes(
            pendingId,
          ),
          "a plain member withdrew an invitation",
        );
      });

      it("keeps a manager's actions to the organization the path names", async () => {
        const base = `/api/organizations/${organization.id}`;
        const withdrawn = await call(
          seats.owner.token,
          "DELETE",
          `${base}/invitations/${rivalInvitationId}`,
        );
        assertEquals(withdrawn.status, 404);
        const revoked = await call(
          seats.owner.token,
          "DELETE",
          `${base}/members/${seats.rivalMember.id}/member`,
        );
        assertEquals(revoked.status, 404);
        assertFalse(
          (await invitationIdsOf(seats.owner.token, organization.id)).includes(
            rivalInvitationId,
          ),
          "one organization's invitations listed another's",
        );
        const rivalBase = `/api/organizations/${rival.id}`;
        for (
          const [method, path] of [
            ["DELETE", `${rivalBase}/invitations/${rivalInvitationId}`],
            ["DELETE", `${rivalBase}/members/${seats.rivalMember.id}/member`],
            ["GET", `${rivalBase}/invitations`],
          ]
        ) {
          const refused = await call(seats.owner.token, method, path);
          assertEquals(refused.status, 404, `${method} ${path}`);
        }
        assert(
          (await invitationIdsOf(seats.rival.token, rival.id)).includes(
            rivalInvitationId,
          ),
          "another organization's manager withdrew this invitation",
        );
        const rivalMembers = await membersOf(seats.rival.token, rival.id);
        assert(
          rivalMembers.body.data.some((row) =>
            row.userId === seats.rivalMember.id
          ),
          "another organization's manager revoked this member",
        );
      });

      it("refuses an invitation from a plain member as it refuses a stranger", async () => {
        const offered = await invite(
          seats.member.token,
          organization.id,
          newEmail(),
          "member",
        );
        assertEquals(offered.status, 404);
      });

      it("refuses a role the tenant has not defined", async () => {
        const offered = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "contract-undefined-role",
        );
        assertEquals(offered.status, 400);
      });

      it("refuses a return_to on an origin with no registered redirect URI", async () => {
        const reply = await call(
          seats.admin.token,
          "POST",
          `/api/organizations/${organization.id}/invitations`,
          {
            email: newEmail(),
            role: "member",
            return_to: "https://unregistered.example/welcome",
          },
        );
        assertEquals(reply.status, 400);
      });

      it("invites an address with no account, lowercased, for its verified holder to accept later", async () => {
        const address = newEmail();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          address.toUpperCase(),
          "member",
        );
        assertEquals(offered.status, 201);
        assert(offered.body.status === "invitation", offered.body.status);
        assertEquals(offered.body.invitation.email, address);
        const invitationId = offered.body.invitation.id;
        const listed = await call<Page<{ id: string }>>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/invitations?status=outstanding`,
        );
        assertEquals(listed.status, 200);
        assert(listed.body.data.some((entry) => entry.id === invitationId));

        const holder = await person({ email: address });
        const waiting = await call<Offers>(
          holder.token,
          "GET",
          "/api/organizations/offers",
        );
        assertEquals(
          waiting.body.offers.map((offer) => offer.id),
          [invitationId],
        );
        const accepted = await accept(holder.token, invitationId);
        assertEquals(accepted.status, "accepted");
        assertEquals(accepted.membership?.organizationId, organization.id);
        assertEquals(
          (await membershipsOf(holder.token)).map((entry) => entry.org_id),
          [organization.id],
        );
      });

      it("hides an invitation from its address's unverified holder and names the address instead", async () => {
        const address = newEmail();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          address,
          "member",
        );
        assert(offered.body.status === "invitation", offered.body.status);
        const holder = await person({ email: address, emailVerified: false });
        const waiting = await call<Offers>(
          holder.token,
          "GET",
          "/api/organizations/offers",
        );
        assertEquals(waiting.body, { offers: [], unverifiedEmail: address });
        assertEquals(
          (await accept(holder.token, offered.body.invitation.id)).status,
          "wrong-account",
        );
      });

      it("converts an invitation only for the address it names", async () => {
        const offered = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "member",
        );
        assert(offered.body.status === "invitation", offered.body.status);
        const other = await person();
        assertEquals(
          (await accept(other.token, offered.body.invitation.id)).status,
          "wrong-account",
        );
      });

      it("withdraws an invitation so that it can no longer be accepted", async () => {
        const address = newEmail();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          address,
          "member",
        );
        assert(offered.body.status === "invitation", offered.body.status);
        const invitationId = offered.body.invitation.id;
        const withdrawn = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/invitations/${invitationId}`,
        );
        assertEquals(withdrawn.status, 204);
        const listed = await call<Page<{ id: string }>>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/invitations`,
        );
        assertFalse(
          listed.body.data.some((entry) => entry.id === invitationId),
        );
        const holder = await person({ email: address });
        assertEquals(
          (await accept(holder.token, invitationId)).status,
          "invalid",
        );
      });

      it("ends a member's access when a manager revokes their tier", async () => {
        const leaver = await person();
        await seat(seats.admin.token, organization.id, leaver, "member");
        const revoked = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${leaver.id}/member`,
        );
        assertEquals(revoked.status, 204);
        assertEquals(await membershipsOf(leaver.token), []);
        const read = await call(
          leaver.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        assertEquals(read.status, 404);
        const again = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${leaver.id}/member`,
        );
        assertEquals(again.status, 404);
      });

      it("never leaves an organization without an owner", async () => {
        const reply = await call(
          seats.owner.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${seats.owner.id}/owner`,
        );
        assertEquals(reply.status, 409);
      });

      it("deletes an organization for its owner alone, and not while it holds a grant", async () => {
        const doomed = await createOrganization(seats.owner.token);
        await seat(seats.owner.token, doomed.id, seats.admin, "admin");
        await seat(seats.owner.token, doomed.id, seats.member, "member");
        const byAdmin = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${doomed.id}`,
        );
        assertEquals(byAdmin.status, 403);
        const byMember = await call(
          seats.member.token,
          "DELETE",
          `/api/organizations/${doomed.id}`,
        );
        assertEquals(byMember.status, 404);

        const holding = await createOrganization(seats.owner.token);
        await tenant.grant({
          resource: { type: "contract_document", id: `held-${holding.id}` },
          subject: { type: "organization", id: holding.id },
          permissions: ["contract:read"],
        });
        const blocked = await call(
          seats.owner.token,
          "DELETE",
          `/api/organizations/${holding.id}`,
        );
        assertEquals(blocked.status, 409);

        const deleted = await call(
          seats.owner.token,
          "DELETE",
          `/api/organizations/${doomed.id}`,
        );
        assertEquals(deleted.status, 204);
        const gone = await call(
          seats.member.token,
          "GET",
          `/api/organizations/${doomed.id}`,
        );
        assertEquals(gone.status, 404);
        assertFalse(
          (await membershipsOf(seats.member.token)).some((entry) =>
            entry.org_id === doomed.id
          ),
        );
      });

      it("refuses a caller with no bearer token", async () => {
        const reply = await call(null, "GET", "/api/organizations");
        assertEquals(reply.status, 401);
      });
    });

    describe("the account API", () => {
      it("answers a new person's own metadata bucket, empty, and no cache keeps it", async () => {
        const caller = await person();
        const reply = await call(caller.token, "GET", "/api/account");
        assertEquals(reply.status, 200);
        assertEquals(reply.body, { userMetadata: {} });
        assertStringIncludes(
          reply.headers.get("cache-control") ?? "",
          "no-store",
        );
      });

      it("merges a patch shallowly, deleting keys set to null and keeping keys it does not name", async () => {
        const caller = await person();
        const first = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { theme: "dark", locale: "en", nested: { a: 1 } },
        });
        assertEquals(first.status, 200);
        assertEquals(first.body, {
          userMetadata: { theme: "dark", locale: "en", nested: { a: 1 } },
        });
        const second = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { locale: null, nested: { b: 2 } },
        });
        assertEquals(second.body, {
          userMetadata: { theme: "dark", nested: { b: 2 } },
        });
        const read = await call(caller.token, "GET", "/api/account");
        assertEquals(read.body, second.body);
      });

      it("refuses anything but a userMetadata object", async () => {
        const caller = await person();
        for (
          const body of [
            {},
            { userMetadata: ["dark"] },
            { userMetadata: {}, metadata: { role: "admin" } },
          ]
        ) {
          const reply = await call(caller.token, "PATCH", "/api/account", body);
          assertEquals(reply.status, 400, JSON.stringify(body));
        }
      });

      it("keeps the bucket to eight levels of nesting", async () => {
        const caller = await person();
        const nested = (levels: number): Record<string, unknown> =>
          levels <= 1 ? { leaf: true } : { next: nested(levels - 1) };
        const deepest = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: nested(8),
        });
        assertEquals(deepest.status, 200);
        const tooDeep = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: nested(9),
        });
        assertEquals(tooDeep.status, 400);
      });

      it("measures the metadata limit in UTF-8 bytes and preserves the bucket on refusal", async () => {
        const caller = await person();
        const notes = "界".repeat(6 * 1024);
        const reply = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { notes },
        });
        assertEquals(reply.status, 400);
        const read = await call(caller.token, "GET", "/api/account");
        assertEquals(read.body, { userMetadata: {} });
      });

      it("keeps the merged bucket to sixteen kilobytes, however small each patch is", async () => {
        const caller = await person();
        const half = "x".repeat(9 * 1024);
        const first = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { first: half },
        });
        assertEquals(first.status, 200);
        const second = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { second: half },
        });
        assertEquals(second.status, 400);
        const read = await call(caller.token, "GET", "/api/account");
        assertEquals(read.body, { userMetadata: { first: half } });
      });

      it("refuses a caller with no bearer token", async () => {
        const reply = await call(null, "GET", "/api/account");
        assertEquals(reply.status, 401);
      });
    });

    describe("the account sessions API", () => {
      interface Session {
        id: string;
        current: boolean;
        createdAt: string;
        lastActiveAt: string;
        ipAddress: string | null;
        userAgent: string | null;
      }

      async function sessionsOf(accessToken: string): Promise<Session[]> {
        const reply = await call<{ sessions: Session[] }>(
          accessToken,
          "GET",
          "/api/account/sessions",
        );
        assertEquals(reply.status, 200);
        return reply.body.sessions;
      }

      const currentOf = (sessions: Session[]) =>
        sessions.filter((session) => session.current).map(({ id }) => id);

      async function refresh(refreshToken: string): Promise<Response> {
        return await send(metadata.token_endpoint, {
          method: "POST",
          headers: { authorization: clientAuth() },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
          }),
        });
      }

      it("lists every sign-in as a session, the credential's own first", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        const second = await tenant.signIn(id);
        const listed = await sessionsOf(second.access_token);
        assertEquals(listed.length, 2);
        assertEquals(currentOf(listed), [listed[0].id]);
        assertEquals(Object.keys(listed[0]).sort(), [
          "createdAt",
          "current",
          "id",
          "ipAddress",
          "lastActiveAt",
          "userAgent",
        ]);
        const fromFirst = await sessionsOf(first.access_token);
        assertEquals(
          fromFirst.map((session) => session.id).sort(),
          listed.map((session) => session.id).sort(),
        );
        assertEquals(currentOf(fromFirst), [listed[1].id]);
      });

      it("keeps a refreshed credential on the session it was issued from", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        await tenant.signIn(id);
        const issuedFrom = currentOf(await sessionsOf(first.access_token));
        const response = await refresh(first.refresh_token);
        assertEquals(response.status, 200);
        const refreshed = await response.json();
        assertEquals(
          currentOf(await sessionsOf(refreshed.access_token)),
          issuedFrom,
        );
      });

      it("refuses to end the caller's own session", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const { access_token } = await tenant.signIn(id);
        const [own] = currentOf(await sessionsOf(access_token));
        const reply = await call<{ reason?: string }>(
          access_token,
          "DELETE",
          `/api/account/sessions/${own}`,
        );
        assertEquals(reply.status, 409);
        assertEquals(reply.body.reason, "current_session");
      });

      it("ends another of the caller's sessions and every token issued from it", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const other = await tenant.signIn(id);
        const current = await tenant.signIn(id);
        const [otherSession] = currentOf(await sessionsOf(other.access_token));
        const ended = await call(
          current.access_token,
          "DELETE",
          `/api/account/sessions/${otherSession}`,
        );
        assertEquals(ended.status, 204);
        assertEquals((await introspect(other.access_token)).active, false);
        const refused = await refresh(other.refresh_token);
        await refused.body?.cancel();
        assertEquals(refused.status, 400);
        const remaining = await sessionsOf(current.access_token);
        assertEquals(remaining.map((session) => session.current), [true]);
      });

      it("answers another person's session, an unknown id and a malformed id with 404", async () => {
        const caller = await person();
        const stranger = await person();
        const [theirs] = currentOf(await sessionsOf(stranger.token));
        for (
          const sessionId of [theirs, crypto.randomUUID(), "not-a-session"]
        ) {
          const reply = await call(
            caller.token,
            "DELETE",
            `/api/account/sessions/${sessionId}`,
          );
          assertEquals(reply.status, 404, sessionId);
        }
        assertEquals((await sessionsOf(stranger.token)).length, 1);
      });

      it("ends every other session and keeps the caller's", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        await tenant.signIn(id);
        const kept = await tenant.signIn(id);
        const reply = await call(
          kept.access_token,
          "POST",
          "/api/account/sessions/revoke-others",
        );
        assertEquals(reply.status, 200);
        assertEquals(reply.body, { revoked: 2 });
        const remaining = await sessionsOf(kept.access_token);
        assertEquals(remaining.map((session) => session.current), [true]);
        assertEquals((await introspect(first.access_token)).active, false);
      });

      it("ends a login session when a token issued from it is revoked", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const revoked = await tenant.signIn(id);
        const kept = await tenant.signIn(id);
        assert(
          metadata.revocation_endpoint,
          "the tenant advertises no revocation endpoint",
        );
        const response = await send(metadata.revocation_endpoint, {
          method: "POST",
          headers: { authorization: clientAuth() },
          body: new URLSearchParams({
            token: revoked.refresh_token,
            token_type_hint: "refresh_token",
          }),
        });
        await response.body?.cancel();
        assertEquals(response.status, 200);
        assertEquals((await introspect(revoked.access_token)).active, false);
        const remaining = await sessionsOf(kept.access_token);
        assertEquals(remaining.map((session) => session.current), [true]);
      });

      it("revokes a login session's earlier credential when the same browser signs in again", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        const again = await tenant.signIn(id, undefined, { sameBrowser: true });
        assertEquals((await introspect(first.access_token)).active, false);
        const refused = await refresh(first.refresh_token);
        await refused.body?.cancel();
        assertEquals(refused.status, 400);
        assertEquals((await introspect(again.access_token)).active, true);
        const listed = await sessionsOf(again.access_token);
        assertEquals(listed.map((session) => session.current), [true]);
      });

      it("refuses a body that names anything", async () => {
        const caller = await person();
        const reply = await call(
          caller.token,
          "POST",
          "/api/account/sessions/revoke-others",
          { userId: caller.id },
        );
        assertEquals(reply.status, 400);
      });
    });

    describe("the linked accounts API", () => {
      interface Linked {
        identities: {
          id: string;
          provider: string;
          displayName: string;
          email: string | null;
          createdAt: string;
        }[];
        hasPassword: boolean;
        connectable: unknown[];
      }

      async function linkedOf(accessToken: string): Promise<Linked> {
        const reply = await call<Linked>(
          accessToken,
          "GET",
          "/api/account/linked-accounts",
        );
        assertEquals(reply.status, 200);
        return reply.body;
      }

      it("lists a person's linked accounts and whether they have a password", async () => {
        const caller = await person();
        const email = newEmail();
        const linked = await tenant.linkAccount(caller.id, {
          provider: "github",
          email,
        });
        const body = await linkedOf(caller.token);
        assertEquals(body.hasPassword, true);
        assert(Array.isArray(body.connectable));
        assertEquals(body.identities.length, 1);
        const [identity] = body.identities;
        assertEquals(identity.id, linked);
        assertEquals(identity.provider, "github");
        assertEquals(identity.email, email);
        assert(identity.displayName, "a linked account names its provider");
        assert(identity.createdAt, "a linked account says when it was linked");
      });

      it("disconnects a linked account while a password remains", async () => {
        const caller = await person();
        const linked = await tenant.linkAccount(caller.id, {
          provider: "github",
          email: null,
        });
        const reply = await call(
          caller.token,
          "DELETE",
          `/api/account/linked-accounts/${linked}`,
        );
        assertEquals(reply.status, 204);
        assertEquals((await linkedOf(caller.token)).identities, []);
      });

      it("refuses to disconnect a person's last way to sign in", async () => {
        const id = await tenant.addUser([], {
          email: newEmail(),
          password: false,
        });
        const linked = await tenant.linkAccount(id, {
          provider: "github",
          email: null,
        });
        const { access_token } = await tenant.signIn(id);
        assertEquals((await linkedOf(access_token)).hasPassword, false);
        const reply = await call<{ reason?: string }>(
          access_token,
          "DELETE",
          `/api/account/linked-accounts/${linked}`,
        );
        assertEquals(reply.status, 409);
        assertEquals(reply.body.reason, "last_method");
        assertEquals(
          (await linkedOf(access_token)).identities.map((entry) => entry.id),
          [linked],
        );
      });

      it("answers another person's linked account, an unknown id and a malformed id with 404", async () => {
        const caller = await person();
        const stranger = await person();
        const theirs = await tenant.linkAccount(stranger.id, {
          provider: "github",
          email: null,
        });
        for (const identityId of [theirs, crypto.randomUUID(), "not-an-id"]) {
          const reply = await call(
            caller.token,
            "DELETE",
            `/api/account/linked-accounts/${identityId}`,
          );
          assertEquals(reply.status, 404, identityId);
        }
        assertEquals(
          (await linkedOf(stranger.token)).identities.map((entry) => entry.id),
          [theirs],
        );
      });
    });
  });
}
