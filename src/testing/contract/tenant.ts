import { afterAll, assert, beforeAll, describe, expect, it } from "vitest";
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
   * Defines a tenant-wide role carrying `permissions`, which an
   * organization's manager may grant a member through
   * `POST /api/organizations/:organizationId/members/:userId/roles`, and
   * returns its id.
   */
  addRole(permissions: string[]): Promise<string>;
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
  /**
   * Registers an application allowed the `client_credentials` grant and no
   * other, whose tokens may carry `options.scopes` and nothing else, and which
   * a tenant administrator has assigned `options.permissions`. It is
   * confidential unless `options.confidential` is `false`. Returns the
   * credentials it signs in with: its id, and its secret when it has one.
   */
  addMachineClient(
    options: TenantContractMachineClientOptions,
  ): Promise<TenantContractClient>;
  /** Releases anything `setup` allocated. */
  cleanup?(): Promise<void> | void;
}

/** An application's credentials at the token endpoint. */
export interface TenantContractClient {
  /** The client id. */
  id: string;
  /** The client secret, which a public application is never issued. */
  secret?: string;
}

/**
 * A management permission a tenant administrator assigns a machine
 * application. The suite assigns `resource_grants.read`, which is what
 * `GET /api/resource-grants` requires.
 */
export type TenantContractMachinePermission = "resource_grants.read";

/** What `TenantContractFixture.addMachineClient` registers. */
export interface TenantContractMachineClientOptions {
  /**
   * The scopes the application's tokens may carry. The suite names
   * `identity:organizations:read` alone, and expects a token asking for any
   * other to be refused.
   */
  scopes: string[];
  /** The permissions an administrator assigned the application. */
  permissions: TenantContractMachinePermission[];
  /**
   * Whether the application is confidential, authenticating with a secret.
   * Defaults to `true`. With `false` it is public and issued no secret, and
   * the suite expects the token endpoint to refuse it the grant as
   * `invalid_client`. A tenant that refuses to register a public application
   * allowed the grant may leave the grant off, since that refusal is client
   * authentication's and comes before the grant is considered.
   */
  confidential?: boolean;
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
  username?: string;
  client_id?: string;
  scope?: string;
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
      expect(response.status).toStrictEqual(200);
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

    const sorted = (values: string[] | undefined) => [...(values ?? [])].sort();

    describe("introspection", () => {
      it("reports tenant-wide permissions and no organization for a sign-in that picked none", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const claims = await introspect(access_token);
        expect(claims.active).toStrictEqual(true);
        expect(claims.sub).toStrictEqual(people.member);
        expect(sorted(claims.permissions)).toStrictEqual(["contract:tenant"]);
        expect(
          claims.org_id,
          "a sign-in with no organization names none",
        ).toBeFalsy();
      });

      it("picks a person's only organization when the sign-in names none", async () => {
        const { access_token } = await tenant.signIn(people.solo);
        const claims = await introspect(access_token);
        expect(claims.org_id).toStrictEqual(organizations.other);
        expect(sorted(claims.permissions)).toStrictEqual(["contract:other"]);
      });

      it("adds the picked organization and its permissions, and no other's", async () => {
        const { access_token } = await tenant.signIn(
          people.member,
          organizations.home,
        );
        const claims = await introspect(access_token);
        expect(claims.org_id).toStrictEqual(organizations.home);
        expect(sorted(claims.permissions)).toStrictEqual([
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
        expect(response.status).toStrictEqual(200);
        const refreshed = await response.json();
        const claims = await introspect(refreshed.access_token);
        expect(claims.org_id).toStrictEqual(organizations.other);
      });

      it("stops answering for an organization once the membership ends", async () => {
        const { access_token } = await tenant.signIn(
          people.leaver,
          organizations.home,
        );
        await tenant.removeMember(organizations.home, people.leaver);
        const claims = await introspect(access_token);
        expect(claims.org_id).toBeFalsy();
        expect(sorted(claims.permissions)).toStrictEqual([]);
      });
    });

    describe("GET /api/memberships", () => {
      it("lists the organizations the caller belongs to, and no others", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const response = await send(
          new URL("/api/memberships", tenant.issuer),
          { headers: { authorization: `Bearer ${access_token}` } },
        );
        expect(response.status).toStrictEqual(200);
        const body = (await response.json()) as {
          memberships: {
            org_id: string;
            org_slug: string;
            name: string;
            roles: string[];
          }[];
          cursor: string | null;
        };
        expect(
          body.memberships.map((membership) => membership.org_id).sort(),
        ).toStrictEqual([organizations.home, organizations.other].sort());
        for (const membership of body.memberships) {
          expect(membership.roles).toStrictEqual(["member"]);
          assert(membership.org_slug, "every membership names its slug");
          assert(membership.name, "every membership names its organization");
        }
        expect(body.cursor).toStrictEqual(null);
      });

      it("refuses a caller with no bearer token", async () => {
        const response = await send(new URL("/api/memberships", tenant.issuer));
        await response.body?.cancel();
        expect(response.status).toStrictEqual(401);
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
        expect(answer.status).toStrictEqual(200);
        expect(answer.body).toStrictEqual({
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
        expect(answer.body).toStrictEqual({
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
        expect(answer.status).toStrictEqual(200);
        expect(answer.body.results).toStrictEqual({ "contract:other": true });
      });

      it("answers an organization the caller does not belong to from tenant-wide permissions alone", async () => {
        const { access_token } = await tenant.signIn(people.member);
        const answer = await ask(access_token, "/api/check", {
          permissions: ["contract:other", "contract:tenant"],
          resource: { type: "organization", id: organizations.unjoined },
        });
        expect(answer.status).toStrictEqual(200);
        expect(answer.body.results).toStrictEqual({
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
        expect(answer.status).toStrictEqual(404);
      });

      it("answers a resource from a grant to the person and from one to their organization", async () => {
        const { access_token } = await tenant.signIn(people.outsider);
        const direct = await ask(access_token, "/api/check", {
          permissions: ["contract:read", "contract:write"],
          resource: { type: "contract_document", id: "direct" },
        });
        expect(direct.status).toStrictEqual(200);
        expect(direct.body.results).toStrictEqual({
          "contract:read": true,
          "contract:write": false,
        });
        const shared = await ask(access_token, "/api/check", {
          permissions: ["contract:write"],
          resource: { type: "contract_document", id: "shared" },
        });
        expect(shared.body.results).toStrictEqual({ "contract:write": true });
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
        expect(answer.body.results).toStrictEqual({
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
        expect(answer.status).toStrictEqual(400);
      });

      it("refuses a caller with no bearer token", async () => {
        const response = await send(new URL("/api/check", tenant.issuer), {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ permissions: ["contract:tenant"] }),
        });
        await response.body?.cancel();
        expect(response.status).toStrictEqual(401);
      });
    });

    describe("POST /api/check/batch", () => {
      it("answers each candidate id as /api/check would", async () => {
        const { access_token } = await tenant.signIn(people.outsider);
        const answer = await ask(access_token, "/api/check/batch", {
          permissions: ["contract:read"],
          resource: { type: "contract_document", ids: ["direct", "unseen"] },
        });
        expect(answer.status).toStrictEqual(200);
        expect(answer.body).toStrictEqual({
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
      expect(reply.status).toStrictEqual(200);
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
      expect(reply.status, JSON.stringify(reply.body)).toStrictEqual(201);
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
      expect(reply.status, JSON.stringify(reply.body)).toStrictEqual(200);
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
      expect(offered.status, JSON.stringify(offered.body)).toStrictEqual(201);
      assert(offered.body.status === "membership", offered.body.status);
      const accepted = await accept(invitee.token, offered.body.membership.id);
      expect(accepted.status).toStrictEqual("accepted");
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
        expect(listed.status).toStrictEqual(200);
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
        expect(created.status).toStrictEqual(201);
        expect(created.body.slug).toStrictEqual(slug);
        expect(created.body.name).toStrictEqual("Contract Created");
        const listed = await call<Page<Organization>>(
          creator.token,
          "GET",
          "/api/organizations",
        );
        expect(listed.status).toStrictEqual(200);
        expect(listed.body.data.map((entry) => entry.id)).toStrictEqual([
          created.body.id,
        ]);
        expect(await membershipsOf(creator.token)).toStrictEqual([
          {
            org_id: created.body.id,
            org_slug: slug,
            name: "Contract Created",
            roles: ["owner"],
          },
        ]);
      });

      it("refuses a slug another organization holds", async () => {
        const reply = await call(
          seats.outsider.token,
          "POST",
          "/api/organizations",
          { name: "Contract Taken", slug: organization.slug },
        );
        expect(reply.status).toStrictEqual(409);
      });

      it("refuses a slug that is not lowercase letters, numbers and single hyphens", async () => {
        const reply = await call(
          seats.outsider.token,
          "POST",
          "/api/organizations",
          { name: "Contract Shouting", slug: "Contract--Shouting" },
        );
        expect(reply.status).toStrictEqual(400);
      });

      it("lets a member of any tier read the organization and its members, and no cache keep them", async () => {
        const organization = await createOrganization(seats.owner.token);
        await seat(seats.owner.token, organization.id, seats.admin, "admin");
        await seat(seats.owner.token, organization.id, seats.member, "member");
        const read = await call<Organization>(
          seats.member.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        expect(read.status).toStrictEqual(200);
        expect(read.body.id).toStrictEqual(organization.id);
        expect(read.body.slug).toStrictEqual(organization.slug);
        expect(read.headers.get("cache-control") ?? "").toContain("no-store");
        const members = await membersOf(seats.member.token, organization.id);
        expect(members.status).toStrictEqual(200);
        expect(members.headers.get("cache-control") ?? "").toContain(
          "no-store",
        );
        expect(
          members.body.data.map((row) => `${row.userId}:${row.role}`).sort(),
        ).toStrictEqual(
          [
            `${seats.admin.id}:admin`,
            `${seats.member.id}:member`,
            `${seats.owner.id}:owner`,
          ].sort(),
        );
        expect(members.body.hasMore).toBeFalsy();
        for (const row of members.body.data) {
          assert(row.id, "every member row names its grant");
          assert(row.name, "every member row names its person");
          assert(row.acceptedAt, "a member row is an accepted grant");
        }
        expect(
          members.body.data.find((row) => row.userId === seats.member.id)
            ?.email,
        ).toStrictEqual(seats.member.email);
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
        expect([
          outsider.status,
          unknown.status,
          malformed.status,
        ]).toStrictEqual([404, 404, 404]);
        expect(outsider.body.detail).toStrictEqual(unknown.body.detail);
        expect(unknown.body.detail).toStrictEqual(malformed.body.detail);
        const members = await membersOf(seats.outsider.token, organization.id);
        expect(members.status).toStrictEqual(404);
      });

      it("lets an owner or admin rename the organization and a plain member not", async () => {
        const renamed = await call<Organization>(
          seats.admin.token,
          "PATCH",
          `/api/organizations/${organization.id}`,
          { name: "Contract Renamed" },
        );
        expect(renamed.status).toStrictEqual(200);
        expect(renamed.body.name).toStrictEqual("Contract Renamed");
        expect(renamed.body.slug).toStrictEqual(organization.slug);
        for (const caller of [seats.member, seats.outsider]) {
          const refused = await call(
            caller.token,
            "PATCH",
            `/api/organizations/${organization.id}`,
            { name: "Contract Hijacked" },
          );
          expect(refused.status).toStrictEqual(404);
        }
      });

      it("lists the membership tiers an invitation may offer, to a manager only", async () => {
        const roles = await call<{ slug: string; name: string }[]>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/member-roles`,
        );
        expect(roles.status).toStrictEqual(200);
        expect(roles.body.slice(0, 3)).toStrictEqual([
          { slug: "owner", name: "Owner" },
          { slug: "admin", name: "Admin" },
          { slug: "member", name: "Member" },
        ]);
        const refused = await call(
          seats.member.token,
          "GET",
          `/api/organizations/${organization.id}/member-roles`,
        );
        expect(refused.status).toStrictEqual(404);
      });

      it("offers an existing person a pending membership that confers nothing until they accept it", async () => {
        const invitee = await person();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          invitee.email,
          "member",
        );
        expect(offered.status).toStrictEqual(201);
        assert(offered.body.status === "membership", offered.body.status);
        expect(offered.body.membership.role).toStrictEqual("member");
        expect(offered.body.membership.acceptedAt).toStrictEqual(null);
        expect(await membershipsOf(invitee.token)).toStrictEqual([]);
        const before = await membersOf(seats.admin.token, organization.id);
        expect(
          before.body.data.some((row) => row.userId === invitee.id),
          "a pending grant is not a member",
        ).toBeFalsy();

        const waiting = await call<Offers>(
          invitee.token,
          "GET",
          "/api/organizations/offers",
        );
        expect(waiting.status).toStrictEqual(200);
        const current = await call<Organization>(
          seats.owner.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        expect(waiting.body).toStrictEqual({
          offers: [
            {
              id: offered.body.membership.id,
              organizationName: current.body.name,
              roleName: "Member",
            },
          ],
          unverifiedEmail: null,
        });

        const accepted = await accept(
          invitee.token,
          offered.body.membership.id,
        );
        expect(accepted.status).toStrictEqual("accepted");
        expect(accepted.membership?.organizationId).toStrictEqual(
          organization.id,
        );
        expect(accepted.membership?.role).toStrictEqual("member");
        expect(
          (await membershipsOf(invitee.token)).map((entry) => entry.roles),
        ).toStrictEqual([["member"]]);
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
        expect(
          (await accept(seats.outsider.token, offerId)).status,
        ).toStrictEqual("invalid");
        expect(
          (await accept(seats.outsider.token, "not-an-offer")).status,
        ).toStrictEqual("invalid");
        expect((await accept(invitee.token, offerId)).status).toStrictEqual(
          "accepted",
        );
      });

      it("refuses a second offer of a role an address already holds or was offered", async () => {
        const stranger = newEmail();
        const first = await invite(
          seats.admin.token,
          organization.id,
          stranger,
          "member",
        );
        expect(first.status).toStrictEqual(201);
        const again = await invite(
          seats.admin.token,
          organization.id,
          stranger,
          "member",
        );
        expect(again.status).toStrictEqual(409);
        const held = await invite(
          seats.admin.token,
          organization.id,
          seats.member.email,
          "member",
        );
        expect(held.status).toStrictEqual(409);
      });

      it("keeps the owner tier to owners", async () => {
        const offered = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "owner",
        );
        expect(offered.status).toStrictEqual(403);
        const revoked = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${seats.owner.id}/owner`,
        );
        expect(revoked.status).toStrictEqual(403);
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
          expect(
            [byMember.status, byStranger.status],
            `${method} ${path}`,
          ).toStrictEqual([404, 404]);
          expect(byMember.body.detail).toStrictEqual(byStranger.body.detail);
        }
        const members = await membersOf(seats.owner.token, organization.id);
        assert(
          members.body.data.some(
            (row) => row.userId === seats.admin.id && row.role === "admin",
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
        expect(withdrawn.status).toStrictEqual(404);
        const revoked = await call(
          seats.owner.token,
          "DELETE",
          `${base}/members/${seats.rivalMember.id}/member`,
        );
        expect(revoked.status).toStrictEqual(404);
        expect(
          (await invitationIdsOf(seats.owner.token, organization.id)).includes(
            rivalInvitationId,
          ),
          "one organization's invitations listed another's",
        ).toBeFalsy();
        const rivalBase = `/api/organizations/${rival.id}`;
        for (const [method, path] of [
          ["DELETE", `${rivalBase}/invitations/${rivalInvitationId}`],
          ["DELETE", `${rivalBase}/members/${seats.rivalMember.id}/member`],
          ["GET", `${rivalBase}/invitations`],
        ]) {
          const refused = await call(seats.owner.token, method, path);
          expect(refused.status, `${method} ${path}`).toStrictEqual(404);
        }
        assert(
          (await invitationIdsOf(seats.rival.token, rival.id)).includes(
            rivalInvitationId,
          ),
          "another organization's manager withdrew this invitation",
        );
        const rivalMembers = await membersOf(seats.rival.token, rival.id);
        assert(
          rivalMembers.body.data.some(
            (row) => row.userId === seats.rivalMember.id,
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
        expect(offered.status).toStrictEqual(404);
      });

      it("refuses a role the tenant has not defined", async () => {
        const offered = await invite(
          seats.admin.token,
          organization.id,
          newEmail(),
          "contract-undefined-role",
        );
        expect(offered.status).toStrictEqual(400);
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
        expect(reply.status).toStrictEqual(400);
      });

      it("invites an address with no account, lowercased, for its verified holder to accept later", async () => {
        const address = newEmail();
        const offered = await invite(
          seats.admin.token,
          organization.id,
          address.toUpperCase(),
          "member",
        );
        expect(offered.status).toStrictEqual(201);
        assert(offered.body.status === "invitation", offered.body.status);
        expect(offered.body.invitation.email).toStrictEqual(address);
        const invitationId = offered.body.invitation.id;
        const listed = await call<Page<{ id: string }>>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/invitations?status=outstanding`,
        );
        expect(listed.status).toStrictEqual(200);
        assert(listed.body.data.some((entry) => entry.id === invitationId));

        const holder = await person({ email: address });
        const waiting = await call<Offers>(
          holder.token,
          "GET",
          "/api/organizations/offers",
        );
        expect(waiting.body.offers.map((offer) => offer.id)).toStrictEqual([
          invitationId,
        ]);
        const accepted = await accept(holder.token, invitationId);
        expect(accepted.status).toStrictEqual("accepted");
        expect(accepted.membership?.organizationId).toStrictEqual(
          organization.id,
        );
        expect(
          (await membershipsOf(holder.token)).map((entry) => entry.org_id),
        ).toStrictEqual([organization.id]);
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
        expect(waiting.body).toStrictEqual({
          offers: [],
          unverifiedEmail: address,
        });
        expect(
          (await accept(holder.token, offered.body.invitation.id)).status,
        ).toStrictEqual("wrong-account");
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
        expect(
          (await accept(other.token, offered.body.invitation.id)).status,
        ).toStrictEqual("wrong-account");
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
        expect(withdrawn.status).toStrictEqual(204);
        const listed = await call<Page<{ id: string }>>(
          seats.admin.token,
          "GET",
          `/api/organizations/${organization.id}/invitations`,
        );
        expect(
          listed.body.data.some((entry) => entry.id === invitationId),
        ).toBeFalsy();
        const holder = await person({ email: address });
        expect((await accept(holder.token, invitationId)).status).toStrictEqual(
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
        expect(revoked.status).toStrictEqual(204);
        expect(await membershipsOf(leaver.token)).toStrictEqual([]);
        const read = await call(
          leaver.token,
          "GET",
          `/api/organizations/${organization.id}`,
        );
        expect(read.status).toStrictEqual(404);
        const again = await call(
          seats.admin.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${leaver.id}/member`,
        );
        expect(again.status).toStrictEqual(404);
      });

      it("never leaves an organization without an owner", async () => {
        const reply = await call(
          seats.owner.token,
          "DELETE",
          `/api/organizations/${organization.id}/members/${seats.owner.id}/owner`,
        );
        expect(reply.status).toStrictEqual(409);
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
        expect(byAdmin.status).toStrictEqual(403);
        const byMember = await call(
          seats.member.token,
          "DELETE",
          `/api/organizations/${doomed.id}`,
        );
        expect(byMember.status).toStrictEqual(404);

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
        expect(blocked.status).toStrictEqual(409);

        const deleted = await call(
          seats.owner.token,
          "DELETE",
          `/api/organizations/${doomed.id}`,
        );
        expect(deleted.status).toStrictEqual(204);
        const gone = await call(
          seats.member.token,
          "GET",
          `/api/organizations/${doomed.id}`,
        );
        expect(gone.status).toStrictEqual(404);
        expect(
          (await membershipsOf(seats.member.token)).some(
            (entry) => entry.org_id === doomed.id,
          ),
        ).toBeFalsy();
      });

      it("refuses a caller with no bearer token", async () => {
        const reply = await call(null, "GET", "/api/organizations");
        expect(reply.status).toStrictEqual(401);
      });

      describe("application roles a manager grants a member", () => {
        const APP_PERMISSION = "contract:app";
        let roleId: string;
        let option: { id?: string; slug: string; name: string };

        interface HeldRole {
          id: string | null;
          builtInRole: string | null;
          organizationId: string | null;
          slug: string;
          name: string;
          permissions: string[];
        }

        interface Assignment {
          id: string;
          subjectId: string;
          roleId: string | null;
          builtInRole: string | null;
          scopeType: string;
          scopeId: string;
          created: boolean;
        }

        beforeAll(async () => {
          roleId = await tenant.addRole([APP_PERMISSION]);
          const listed = await call<
            { id?: string; slug: string; name: string }[]
          >(
            seats.admin.token,
            "GET",
            `/api/organizations/${organization.id}/member-roles`,
          );
          expect(listed.status).toStrictEqual(200);
          const found = listed.body.find((entry) => entry.id === roleId);
          assert(found, "member-roles does not list the role by its id");
          option = found;
        });

        const rolesPath = (userId: string, organizationId = organization.id) =>
          `/api/organizations/${organizationId}/members/${userId}/roles`;

        async function seated(): Promise<Person> {
          const seatedPerson = await person();
          await seat(
            seats.owner.token,
            organization.id,
            seatedPerson,
            "member",
          );
          return seatedPerson;
        }

        async function grantRole(
          managerToken: string,
          userId: string,
          id = roleId,
          organizationId = organization.id,
        ): Promise<Reply<Assignment>> {
          return await call<Assignment>(
            managerToken,
            "POST",
            rolesPath(userId, organizationId),
            { roleId: id },
          );
        }

        async function heldBy(
          userId: string,
          managerToken = seats.admin.token,
          organizationId = organization.id,
        ): Promise<HeldRole[]> {
          const reply = await call<HeldRole[]>(
            managerToken,
            "GET",
            rolesPath(userId, organizationId),
          );
          expect(reply.status, JSON.stringify(reply.body)).toStrictEqual(200);
          return reply.body;
        }

        async function holds(
          accessToken: string,
          organizationId?: string,
        ): Promise<boolean> {
          const reply = await ask(accessToken, "/api/check", {
            permissions: [APP_PERMISSION],
            ...(organizationId
              ? { resource: { type: "organization", id: organizationId } }
              : {}),
          });
          expect(reply.status).toStrictEqual(200);
          return (reply.body.results as Record<string, boolean>)[
            APP_PERMISSION
          ];
        }

        async function offersOf(accessToken: string): Promise<string[]> {
          const reply = await call<Offers>(
            accessToken,
            "GET",
            "/api/organizations/offers",
          );
          expect(reply.status).toStrictEqual(200);
          return reply.body.offers.map((offer) => offer.id).sort();
        }

        it("names a tenant-wide role in member-roles by the id a grant takes, and no built-in tier by any", async () => {
          expect(option.id).toStrictEqual(roleId);
          assert(option.slug, "the role is listed by its slug");
          assert(option.name, "the role is listed by its name");
          const listed = await call<{ id?: string; slug: string }[]>(
            seats.owner.token,
            "GET",
            `/api/organizations/${organization.id}/member-roles`,
          );
          for (const slug of ["owner", "admin", "member"]) {
            const tier = listed.body.find((entry) => entry.slug === slug);
            assert(tier, `the built-in ${slug} tier is listed`);
            expect(
              "id" in tier,
              `the built-in ${slug} tier has an id`,
            ).toBeFalsy();
          }
        });

        it("grants an accepted member a role that counts inside the organization only", async () => {
          const member = await seated();
          await seat(seats.rival.token, rival.id, member, "member");
          expect(await holds(member.token, organization.id)).toBeFalsy();
          const granted = await grantRole(seats.admin.token, member.id);
          expect(granted.status, JSON.stringify(granted.body)).toStrictEqual(
            201,
          );
          expect(granted.body.subjectId).toStrictEqual(member.id);
          expect(granted.body.roleId).toStrictEqual(roleId);
          expect(granted.body.builtInRole).toStrictEqual(null);
          expect(granted.body.scopeType).toStrictEqual("organization");
          expect(granted.body.scopeId).toStrictEqual(organization.id);
          expect(granted.body.created).toStrictEqual(true);
          assert(await holds(member.token, organization.id));
          expect(
            await holds(member.token),
            "a role held in an organization answered at tenant scope",
          ).toBeFalsy();
          expect(
            await holds(member.token, rival.id),
            "a role held in one organization answered for another it belongs to",
          ).toBeFalsy();
          expect(await heldBy(member.id)).toStrictEqual([
            {
              id: roleId,
              builtInRole: null,
              organizationId: null,
              slug: option.slug,
              name: option.name,
              permissions: [APP_PERMISSION],
            },
          ]);
          const again = await grantRole(seats.owner.token, member.id);
          expect(again.status).toStrictEqual(201);
          expect(again.body.id).toStrictEqual(granted.body.id);
          expect(again.body.created).toStrictEqual(false);
          expect((await heldBy(member.id)).length).toStrictEqual(1);
        });

        it("revokes a role, after which the permission stops answering and the role is not found", async () => {
          const member = await seated();
          expect(
            (await grantRole(seats.admin.token, member.id)).status,
          ).toStrictEqual(201);
          const revoked = await call(
            seats.admin.token,
            "DELETE",
            `${rolesPath(member.id)}/${roleId}`,
          );
          expect(revoked.status).toStrictEqual(204);
          expect(await holds(member.token, organization.id)).toBeFalsy();
          expect(await heldBy(member.id)).toStrictEqual([]);
          const again = await call(
            seats.admin.token,
            "DELETE",
            `${rolesPath(member.id)}/${roleId}`,
          );
          expect(again.status).toStrictEqual(404);
        });

        it("refuses a plain member and a stranger every verb with the 404 an unknown organization gets, and changes nothing", async () => {
          const member = await seated();
          expect(
            (await grantRole(seats.admin.token, member.id)).status,
          ).toStrictEqual(201);
          const unknown = crypto.randomUUID();
          const verbs: [string, (organizationId: string) => string, unknown][] =
            [
              ["GET", (id) => rolesPath(member.id, id), undefined],
              ["POST", (id) => rolesPath(member.id, id), { roleId }],
              [
                "DELETE",
                (id) => `${rolesPath(member.id, id)}/${roleId}`,
                undefined,
              ],
            ];
          for (const [method, path, body] of verbs) {
            const onUnknown = await call<{ detail?: string }>(
              seats.owner.token,
              method,
              path(unknown),
              body,
            );
            expect(
              onUnknown.status,
              `${method} on an unknown id`,
            ).toStrictEqual(404);
            for (const caller of [seats.member, seats.outsider]) {
              const refused = await call<{ detail?: string }>(
                caller.token,
                method,
                path(organization.id),
                body,
              );
              expect(
                refused.status,
                `${method} below the manager tier`,
              ).toStrictEqual(404);
              expect(refused.body.detail).toStrictEqual(onUnknown.body.detail);
            }
          }
          assert(
            await holds(member.token, organization.id),
            "a refused revoke took the role away",
          );
        });

        it("answers a pending member, a non-member and an unknown user with one 404, granting nothing", async () => {
          const pending = await person();
          const offered = await invite(
            seats.admin.token,
            organization.id,
            pending.email,
            "member",
          );
          assert(offered.body.status === "membership", offered.body.status);
          const details = new Set<string | undefined>();
          for (const userId of [
            pending.id,
            seats.outsider.id,
            crypto.randomUUID(),
          ]) {
            const read = await call<{ detail?: string }>(
              seats.admin.token,
              "GET",
              rolesPath(userId),
            );
            const granted = await grantRole(seats.admin.token, userId);
            expect([read.status, granted.status], userId).toStrictEqual([
              404, 404,
            ]);
            details.add(read.body.detail);
            details.add((granted.body as { detail?: string }).detail);
          }
          expect(details.size, [...details].join(" | ")).toStrictEqual(1);
          expect(
            (await accept(pending.token, offered.body.membership.id)).status,
          ).toStrictEqual("accepted");
          expect(await heldBy(pending.id)).toStrictEqual([]);
          expect(await holds(pending.token, organization.id)).toBeFalsy();
        });

        it("refuses a role the tenant does not know with 404, and a grant that names no role with 400", async () => {
          const member = await seated();
          const unknown = await grantRole(
            seats.admin.token,
            member.id,
            crypto.randomUUID(),
          );
          expect(unknown.status).toStrictEqual(404);
          const unnamed = await call(
            seats.admin.token,
            "POST",
            rolesPath(member.id),
            {},
          );
          expect(unnamed.status).toStrictEqual(400);
          expect(await heldBy(member.id)).toStrictEqual([]);
        });

        it("refuses a manager revoking a built-in role they do not hold there, and answers any other name with 404", async () => {
          const member = await seated();
          const asAdmin = await call(
            seats.admin.token,
            "DELETE",
            `${rolesPath(member.id)}/owner`,
          );
          expect(asAdmin.status).toStrictEqual(403);
          const asOwner = await call(
            seats.owner.token,
            "DELETE",
            `${rolesPath(member.id)}/member`,
          );
          expect(
            asOwner.status,
            "an owner membership is not a built-in role held there",
          ).toStrictEqual(403);
          const unnamed = await call(
            seats.owner.token,
            "DELETE",
            `${rolesPath(member.id)}/not-a-role`,
          );
          expect(unnamed.status).toStrictEqual(404);
        });

        it("ends the roles and open offers a person's last membership carried, so rejoining restores nothing", async () => {
          const address = newEmail();
          const invited = await invite(
            seats.owner.token,
            organization.id,
            address,
            "admin",
          );
          assert(invited.body.status === "invitation", invited.body.status);
          const invitationId = invited.body.invitation.id;
          const leaver = await person({ email: address });
          await seat(seats.owner.token, organization.id, leaver, "member");
          const ownerOffer = await invite(
            seats.owner.token,
            organization.id,
            address,
            "owner",
          );
          assert(
            ownerOffer.body.status === "membership",
            ownerOffer.body.status,
          );
          expect(
            (await grantRole(seats.admin.token, leaver.id)).status,
          ).toStrictEqual(201);
          expect(await offersOf(leaver.token)).toStrictEqual(
            [invitationId, ownerOffer.body.membership.id].sort(),
          );

          const revoked = await call(
            seats.admin.token,
            "DELETE",
            `/api/organizations/${organization.id}/members/${leaver.id}/member`,
          );
          expect(revoked.status).toStrictEqual(204);
          expect(await offersOf(leaver.token)).toStrictEqual([]);
          expect(
            (
              await invitationIdsOf(seats.owner.token, organization.id)
            ).includes(invitationId),
            "an invitation to the leaver's address outlived their membership",
          ).toBeFalsy();
          const read = await call(
            seats.admin.token,
            "GET",
            rolesPath(leaver.id),
          );
          expect(read.status).toStrictEqual(404);

          await seat(seats.owner.token, organization.id, leaver, "member");
          expect(await heldBy(leaver.id)).toStrictEqual([]);
          expect(
            await holds(leaver.token, organization.id),
            "rejoining restored a role the last membership carried",
          ).toBeFalsy();
        });

        it("keeps a role revoke and a membership's end to the person and organization they name", async () => {
          const address = newEmail();
          const elsewhere = await invite(
            seats.rival.token,
            rival.id,
            address,
            "member",
          );
          assert(elsewhere.body.status === "invitation", elsewhere.body.status);
          const leaver = await person({ email: address });
          await seat(seats.owner.token, organization.id, leaver, "member");
          const bystander = await seated();
          await seat(seats.rival.token, rival.id, bystander, "member");
          for (const userId of [leaver.id, bystander.id]) {
            expect(
              (await grantRole(seats.admin.token, userId)).status,
            ).toStrictEqual(201);
          }
          expect(
            (await grantRole(seats.rival.token, bystander.id, roleId, rival.id))
              .status,
          ).toStrictEqual(201);

          const revoked = await call(
            seats.admin.token,
            "DELETE",
            `/api/organizations/${organization.id}/members/${leaver.id}/member`,
          );
          expect(revoked.status).toStrictEqual(204);
          expect(
            (await heldBy(bystander.id)).map((role) => role.id),
            "one person's membership ending took another's role",
          ).toStrictEqual([roleId]);
          assert(
            (await invitationIdsOf(seats.rival.token, rival.id)).includes(
              elsewhere.body.invitation.id,
            ),
            "a membership ending here withdrew an invitation elsewhere",
          );

          for (const status of [204, 404]) {
            const taken = await call(
              seats.admin.token,
              "DELETE",
              `${rolesPath(bystander.id)}/${roleId}`,
            );
            expect(taken.status).toStrictEqual(status);
          }
          expect(
            (await heldBy(bystander.id, seats.rival.token, rival.id)).map(
              (role) => role.id,
            ),
            "a revoke here took the role held in another organization",
          ).toStrictEqual([roleId]);
        });

        it("withdraws only the offer named from someone who is not a member", async () => {
          const invitee = await person();
          const offers: string[] = [];
          for (const role of ["member", "admin"]) {
            const offered = await invite(
              seats.owner.token,
              organization.id,
              invitee.email,
              role,
            );
            assert(offered.body.status === "membership", offered.body.status);
            offers.push(offered.body.membership.id);
          }
          const withdrawn = await call(
            seats.owner.token,
            "DELETE",
            `/api/organizations/${organization.id}/members/${invitee.id}/member`,
          );
          expect(withdrawn.status).toStrictEqual(204);
          expect(await offersOf(invitee.token)).toStrictEqual([offers[1]]);
        });

        it("ends nothing while the person keeps another accepted role there", async () => {
          const stayer = await seated();
          await seat(seats.owner.token, organization.id, stayer, "admin");
          const ownerOffer = await invite(
            seats.owner.token,
            organization.id,
            stayer.email,
            "owner",
          );
          assert(
            ownerOffer.body.status === "membership",
            ownerOffer.body.status,
          );
          expect(
            (await grantRole(seats.owner.token, stayer.id)).status,
          ).toStrictEqual(201);
          const revoked = await call(
            seats.owner.token,
            "DELETE",
            `/api/organizations/${organization.id}/members/${stayer.id}/member`,
          );
          expect(revoked.status).toStrictEqual(204);
          expect(
            (await heldBy(stayer.id)).map((role) => role.id),
          ).toStrictEqual([roleId]);
          assert(await holds(stayer.token, organization.id));
          expect(await offersOf(stayer.token)).toStrictEqual([
            ownerOffer.body.membership.id,
          ]);

          const withdrawn = await call(
            seats.owner.token,
            "DELETE",
            `/api/organizations/${organization.id}/members/${stayer.id}/owner`,
          );
          expect(withdrawn.status).toStrictEqual(204);
          expect(await offersOf(stayer.token)).toStrictEqual([]);
          assert(
            await holds(stayer.token, organization.id),
            "withdrawing a pending offer ended a role",
          );
        });
      });
    });

    describe("the account API", () => {
      it("answers a new person's own metadata bucket, empty, and no cache keeps it", async () => {
        const caller = await person();
        const reply = await call(caller.token, "GET", "/api/account");
        expect(reply.status).toStrictEqual(200);
        expect(reply.body).toStrictEqual({ userMetadata: {} });
        expect(reply.headers.get("cache-control") ?? "").toContain("no-store");
      });

      it("merges a patch shallowly, deleting keys set to null and keeping keys it does not name", async () => {
        const caller = await person();
        const first = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { theme: "dark", locale: "en", nested: { a: 1 } },
        });
        expect(first.status).toStrictEqual(200);
        expect(first.body).toStrictEqual({
          userMetadata: { theme: "dark", locale: "en", nested: { a: 1 } },
        });
        const second = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { locale: null, nested: { b: 2 } },
        });
        expect(second.body).toStrictEqual({
          userMetadata: { theme: "dark", nested: { b: 2 } },
        });
        const read = await call(caller.token, "GET", "/api/account");
        expect(read.body).toStrictEqual(second.body);
      });

      it("refuses anything but a userMetadata object", async () => {
        const caller = await person();
        for (const body of [
          {},
          { userMetadata: ["dark"] },
          { userMetadata: {}, metadata: { role: "admin" } },
        ]) {
          const reply = await call(caller.token, "PATCH", "/api/account", body);
          expect(reply.status, JSON.stringify(body)).toStrictEqual(400);
        }
      });

      it("keeps the bucket to eight levels of nesting", async () => {
        const caller = await person();
        const nested = (levels: number): Record<string, unknown> =>
          levels <= 1 ? { leaf: true } : { next: nested(levels - 1) };
        const deepest = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: nested(8),
        });
        expect(deepest.status).toStrictEqual(200);
        const tooDeep = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: nested(9),
        });
        expect(tooDeep.status).toStrictEqual(400);
      });

      it("measures the metadata limit in UTF-8 bytes and preserves the bucket on refusal", async () => {
        const caller = await person();
        const notes = "界".repeat(6 * 1024);
        const reply = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { notes },
        });
        expect(reply.status).toStrictEqual(400);
        const read = await call(caller.token, "GET", "/api/account");
        expect(read.body).toStrictEqual({ userMetadata: {} });
      });

      it("keeps the merged bucket to sixteen kilobytes, however small each patch is", async () => {
        const caller = await person();
        const half = "x".repeat(9 * 1024);
        const first = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { first: half },
        });
        expect(first.status).toStrictEqual(200);
        const second = await call(caller.token, "PATCH", "/api/account", {
          userMetadata: { second: half },
        });
        expect(second.status).toStrictEqual(400);
        const read = await call(caller.token, "GET", "/api/account");
        expect(read.body).toStrictEqual({ userMetadata: { first: half } });
      });

      it("refuses a caller with no bearer token", async () => {
        const reply = await call(null, "GET", "/api/account");
        expect(reply.status).toStrictEqual(401);
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
        expect(reply.status).toStrictEqual(200);
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
        expect(listed.length).toStrictEqual(2);
        expect(currentOf(listed)).toStrictEqual([listed[0].id]);
        expect(Object.keys(listed[0]).sort()).toStrictEqual([
          "createdAt",
          "current",
          "id",
          "ipAddress",
          "lastActiveAt",
          "userAgent",
        ]);
        const fromFirst = await sessionsOf(first.access_token);
        expect(fromFirst.map((session) => session.id).sort()).toStrictEqual(
          listed.map((session) => session.id).sort(),
        );
        expect(currentOf(fromFirst)).toStrictEqual([listed[1].id]);
      });

      it("leaves an earlier sign-in's credential live when another browser signs in", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        const second = await tenant.signIn(id);
        expect((await introspect(first.access_token)).active).toStrictEqual(
          true,
        );
        expect((await introspect(second.access_token)).active).toStrictEqual(
          true,
        );
        const fromFirst = await sessionsOf(first.access_token);
        const fromSecond = await sessionsOf(second.access_token);
        expect(fromFirst.length).toStrictEqual(2);
        expect(currentOf(fromFirst).length).toStrictEqual(1);
        expect(
          currentOf(fromFirst)[0] === currentOf(fromSecond)[0],
          "two browsers' sign-ins shared one login session",
        ).toBeFalsy();
      });

      it("keeps a refreshed credential on the session it was issued from", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        await tenant.signIn(id);
        const issuedFrom = currentOf(await sessionsOf(first.access_token));
        const response = await refresh(first.refresh_token);
        expect(response.status).toStrictEqual(200);
        const refreshed = await response.json();
        expect(
          currentOf(await sessionsOf(refreshed.access_token)),
        ).toStrictEqual(issuedFrom);
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
        expect(reply.status).toStrictEqual(409);
        expect(reply.body.reason).toStrictEqual("current_session");
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
        expect(ended.status).toStrictEqual(204);
        expect((await introspect(other.access_token)).active).toStrictEqual(
          false,
        );
        const refused = await refresh(other.refresh_token);
        await refused.body?.cancel();
        expect(refused.status).toStrictEqual(400);
        const remaining = await sessionsOf(current.access_token);
        expect(remaining.map((session) => session.current)).toStrictEqual([
          true,
        ]);
      });

      it("answers another person's session, an unknown id and a malformed id with 404", async () => {
        const caller = await person();
        const stranger = await person();
        const [theirs] = currentOf(await sessionsOf(stranger.token));
        for (const sessionId of [
          theirs,
          crypto.randomUUID(),
          "not-a-session",
        ]) {
          const reply = await call(
            caller.token,
            "DELETE",
            `/api/account/sessions/${sessionId}`,
          );
          expect(reply.status, sessionId).toStrictEqual(404);
        }
        expect((await sessionsOf(stranger.token)).length).toStrictEqual(1);
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
        expect(reply.status).toStrictEqual(200);
        expect(reply.body).toStrictEqual({ revoked: 2 });
        const remaining = await sessionsOf(kept.access_token);
        expect(remaining.map((session) => session.current)).toStrictEqual([
          true,
        ]);
        expect((await introspect(first.access_token)).active).toStrictEqual(
          false,
        );
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
        expect(response.status).toStrictEqual(200);
        expect((await introspect(revoked.access_token)).active).toStrictEqual(
          false,
        );
        const remaining = await sessionsOf(kept.access_token);
        expect(remaining.map((session) => session.current)).toStrictEqual([
          true,
        ]);
      });

      it("revokes a login session's earlier credential when the same browser signs in again", async () => {
        const id = await tenant.addUser([], { email: newEmail() });
        const first = await tenant.signIn(id);
        const again = await tenant.signIn(id, undefined, { sameBrowser: true });
        expect((await introspect(first.access_token)).active).toStrictEqual(
          false,
        );
        const refused = await refresh(first.refresh_token);
        await refused.body?.cancel();
        expect(refused.status).toStrictEqual(400);
        expect((await introspect(again.access_token)).active).toStrictEqual(
          true,
        );
        const listed = await sessionsOf(again.access_token);
        expect(listed.map((session) => session.current)).toStrictEqual([true]);
      });

      it("refuses a body that names anything", async () => {
        const caller = await person();
        const reply = await call(
          caller.token,
          "POST",
          "/api/account/sessions/revoke-others",
          { userId: caller.id },
        );
        expect(reply.status).toStrictEqual(400);
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
        expect(reply.status).toStrictEqual(200);
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
        expect(body.hasPassword).toStrictEqual(true);
        assert(Array.isArray(body.connectable));
        expect(body.identities.length).toStrictEqual(1);
        const [identity] = body.identities;
        expect(identity.id).toStrictEqual(linked);
        expect(identity.provider).toStrictEqual("github");
        expect(identity.email).toStrictEqual(email);
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
        expect(reply.status).toStrictEqual(204);
        expect((await linkedOf(caller.token)).identities).toStrictEqual([]);
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
        expect((await linkedOf(access_token)).hasPassword).toStrictEqual(false);
        const reply = await call<{ reason?: string }>(
          access_token,
          "DELETE",
          `/api/account/linked-accounts/${linked}`,
        );
        expect(reply.status).toStrictEqual(409);
        expect(reply.body.reason).toStrictEqual("last_method");
        expect(
          (await linkedOf(access_token)).identities.map((entry) => entry.id),
        ).toStrictEqual([linked]);
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
          expect(reply.status, identityId).toStrictEqual(404);
        }
        expect(
          (await linkedOf(stranger.token)).identities.map((entry) => entry.id),
        ).toStrictEqual([theirs]);
      });
    });

    describe("client credentials and the resource-grants API", () => {
      const ORGANIZATIONS_READ = "identity:organizations:read";
      const DIRECT = "type=contract_document&id=direct";
      const RANKED = "type=contract_document&id=ranked";
      let reader: ConfidentialClient;
      let unassigned: ConfidentialClient;
      let readerToken: string;
      let userinfoEndpoint: string;

      type ConfidentialClient = Required<TenantContractClient>;

      async function addConfidentialClient(
        permissions: TenantContractMachinePermission[],
      ): Promise<ConfidentialClient> {
        const client = await tenant.addMachineClient({
          scopes: [ORGANIZATIONS_READ],
          permissions,
        });
        assert(client.secret, "a confidential application is issued a secret");
        return { id: client.id, secret: client.secret };
      }

      interface MachineTokens {
        access_token?: string;
        refresh_token?: string;
        token_type?: string;
        error?: string;
      }

      interface GrantRow {
        id: string;
        subjectType: string;
        subjectId: string;
        subjectRole: string | null;
        subjectName: string | null;
        subjectActive: boolean;
        roleId: string | null;
        builtInRole: string | null;
        roleSlug: string;
        roleName: string;
      }

      interface GrantList {
        resource: { type: string; id: string };
        grants: GrantRow[];
      }

      async function machineToken(
        client: TenantContractClient,
        scope?: string,
      ): Promise<Reply<MachineTokens>> {
        const response = await send(metadata.token_endpoint, {
          method: "POST",
          headers:
            client.secret === undefined
              ? {}
              : { authorization: encodeBasicAuth(client.id, client.secret) },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            ...(client.secret === undefined ? { client_id: client.id } : {}),
            ...(scope === undefined ? {} : { scope }),
          }),
        });
        const text = await response.text();
        return {
          status: response.status,
          headers: response.headers,
          body: text ? JSON.parse(text) : null,
        };
      }

      async function issuedTo(
        client: TenantContractClient,
        scope?: string,
      ): Promise<string> {
        const issued = await machineToken(client, scope);
        expect(issued.status, JSON.stringify(issued.body)).toStrictEqual(200);
        assert(issued.body.access_token);
        return issued.body.access_token;
      }

      async function introspectAs(
        client: ConfidentialClient,
        accessToken: string,
      ): Promise<Introspection> {
        const response = await send(metadata.introspection_endpoint, {
          method: "POST",
          headers: { authorization: encodeBasicAuth(client.id, client.secret) },
          body: new URLSearchParams({ token: accessToken }),
        });
        expect(response.status).toStrictEqual(200);
        return await response.json();
      }

      function grantsOn(
        accessToken: string | null,
        query: string,
      ): Promise<Reply<GrantList>> {
        return call<GrantList>(
          accessToken,
          "GET",
          `/api/resource-grants?${query}`,
        );
      }

      beforeAll(async () => {
        const response = await send(
          new URL("/.well-known/openid-configuration", tenant.issuer),
        );
        ({ userinfo_endpoint: userinfoEndpoint } = await response.json());
        reader = await addConfidentialClient(["resource_grants.read"]);
        unassigned = await addConfidentialClient([]);
        readerToken = await issuedTo(reader, ORGANIZATIONS_READ);
        const ranked: [string, "user" | "organization", string][] = [
          ["contract:review", "user", people.member],
          ["contract:share", "user", people.outsider],
          ["contract:approve", "user", people.leaver],
          ["contract:comment", "user", people.solo],
          ["contract:audit", "organization", organizations.home],
        ];
        for (const [permission, type, id] of ranked) {
          await tenant.grant({
            resource: { type: "contract_document", id: "ranked" },
            subject: { type, id },
            permissions: [permission],
          });
        }
      });

      it("issues a machine token with no refresh token, naming no person and no organization", async () => {
        const issued = await machineToken(reader, ORGANIZATIONS_READ);
        expect(issued.status, JSON.stringify(issued.body)).toStrictEqual(200);
        expect(issued.body.token_type).toStrictEqual("Bearer");
        assert(issued.body.access_token);
        expect(
          "refresh_token" in issued.body,
          "a machine token has no refresh token",
        ).toBeFalsy();
        const claims = await introspectAs(reader, issued.body.access_token);
        expect(claims.active).toStrictEqual(true);
        expect(claims.client_id).toStrictEqual(reader.id);
        expect(claims.scope).toStrictEqual(ORGANIZATIONS_READ);
        expect(claims.sub, "a machine token names no person").toBeFalsy();
        expect(claims.username, "a machine token names no person").toBeFalsy();
        expect(
          claims.org_id,
          "a machine token belongs to no organization",
        ).toBeFalsy();
        expect(sorted(claims.permissions)).toStrictEqual([]);
      });

      it("answers another application introspecting a machine token that it is inactive", async () => {
        const claims = await introspectAs(unassigned, readerToken);
        expect(claims).toStrictEqual({ active: false });
      });

      it("refuses the grant to a public application, which has no secret to authenticate with", async () => {
        const open = await tenant.addMachineClient({
          scopes: [ORGANIZATIONS_READ],
          permissions: [],
          confidential: false,
        });
        expect(
          open.secret,
          "a public application is issued no secret",
        ).toBeFalsy();
        const refused = await machineToken(open, ORGANIZATIONS_READ);
        expect(refused.status, JSON.stringify(refused.body)).toStrictEqual(401);
        expect(refused.body.error).toStrictEqual("invalid_client");
        expect(refused.body.access_token).toBeFalsy();
      });

      it("refuses the grant to an application not registered for it, and refuses a machine token an OIDC scope or one outside its allowlist", async () => {
        const interactive = await machineToken(
          tenant.client,
          ORGANIZATIONS_READ,
        );
        expect(interactive.status).toStrictEqual(401);
        expect(interactive.body.error).toStrictEqual("unauthorized_client");
        for (const scope of [
          "openid",
          `${ORGANIZATIONS_READ} identity:organizations:write`,
        ]) {
          const refused = await machineToken(reader, scope);
          expect(refused.status, scope).toStrictEqual(400);
          expect(refused.body.error, scope).toStrictEqual("invalid_scope");
        }
      });

      it("accepts organization_id on the refresh_token grant alone", async () => {
        const response = await send(metadata.token_endpoint, {
          method: "POST",
          headers: { authorization: encodeBasicAuth(reader.id, reader.secret) },
          body: new URLSearchParams({
            grant_type: "client_credentials",
            scope: ORGANIZATIONS_READ,
            organization_id: organizations.home,
          }),
        });
        const body = await response.json();
        expect(response.status, JSON.stringify(body)).toStrictEqual(400);
        expect(body.error).toStrictEqual("invalid_request");
      });

      it("refuses a machine token wherever the tenant answers for a person", async () => {
        const checked = await ask(readerToken, "/api/check", {
          permissions: ["contract:tenant"],
        });
        expect(checked.status).toStrictEqual(403);
        expect(checked.body.reason).toStrictEqual("machine_token");
        const batch = await ask(readerToken, "/api/check/batch", {
          permissions: ["contract:read"],
          resource: { type: "contract_document", ids: ["direct"] },
        });
        expect(batch.status).toStrictEqual(403);
        expect(batch.body.reason).toStrictEqual("machine_token");
        for (const path of ["/api/memberships", "/api/account"]) {
          const reply = await call<{ reason?: string }>(
            readerToken,
            "GET",
            path,
          );
          expect(reply.status, path).toStrictEqual(403);
          expect(reply.body.reason, path).toStrictEqual("machine_token");
        }
        const organizations = await call(
          readerToken,
          "GET",
          "/api/organizations",
        );
        expect(organizations.status).toStrictEqual(403);
        const userinfo = await send(userinfoEndpoint, {
          headers: { authorization: `Bearer ${readerToken}` },
        });
        await userinfo.body?.cancel();
        expect(userinfo.status).toStrictEqual(401);
      });

      it("lists who holds a grant on a resource, roles named, and an empty list where nobody does", async () => {
        const direct = await grantsOn(readerToken, DIRECT);
        expect(direct.status, JSON.stringify(direct.body)).toStrictEqual(200);
        expect(direct.headers.get("cache-control") ?? "").toContain("no-store");
        expect(direct.body.resource).toStrictEqual({
          type: "contract_document",
          id: "direct",
        });
        expect(direct.body.grants.length).toStrictEqual(1);
        const [held] = direct.body.grants;
        expect(Object.keys(held).sort()).toStrictEqual([
          "builtInRole",
          "id",
          "roleId",
          "roleName",
          "roleSlug",
          "subjectActive",
          "subjectId",
          "subjectName",
          "subjectRole",
          "subjectType",
        ]);
        expect(held.subjectType).toStrictEqual("user");
        expect(held.subjectId).toStrictEqual(people.outsider);
        expect(held.subjectRole).toStrictEqual(null);
        expect(held.subjectActive).toStrictEqual(true);
        assert(held.subjectName, "a grant names its holder");
        assert(held.id, "a grant has an id");
        assert(held.roleId, "a grant names its role");
        assert(held.roleSlug, "a grant names its role's slug");
        assert(held.roleName, "a grant names its role's name");
        expect(held.builtInRole).toStrictEqual(null);

        const shared = await grantsOn(
          readerToken,
          "type=contract_document&id=shared",
        );
        expect(shared.status).toStrictEqual(200);
        expect(
          shared.body.grants.map((grant) => [
            grant.subjectType,
            grant.subjectId,
          ]),
        ).toStrictEqual([["organization", organizations.home]]);

        const nobody = await grantsOn(
          readerToken,
          `type=contract_document&id=nobody-${crypto.randomUUID()}`,
        );
        expect(nobody.status).toStrictEqual(200);
        expect(nobody.body.grants).toStrictEqual([]);
      });

      it("lists the grants on one resource in role-name order", async () => {
        const ranked = await grantsOn(readerToken, RANKED);
        expect(ranked.status, JSON.stringify(ranked.body)).toStrictEqual(200);
        expect(
          ranked.body.grants.map((grant) => grant.subjectId).sort(),
        ).toStrictEqual(
          [
            people.member,
            people.outsider,
            people.leaver,
            people.solo,
            organizations.home,
          ].sort(),
        );
        const names = ranked.body.grants.map((grant) => grant.roleName);
        expect(
          new Set(names).size,
          "each grant confers a role of its own",
        ).toStrictEqual(names.length);
        expect(names).toStrictEqual(
          [...names].sort((a, b) => a.localeCompare(b)),
        );
      });

      it("hides the listing from a machine token without the permission or the scope, and refuses a person's token and no token", async () => {
        const withoutPermission = await issuedTo(
          unassigned,
          ORGANIZATIONS_READ,
        );
        expect(
          (await grantsOn(withoutPermission, DIRECT)).status,
        ).toStrictEqual(404);
        const withoutScope = await issuedTo(reader);
        expect((await grantsOn(withoutScope, DIRECT)).status).toStrictEqual(
          404,
        );
        const { access_token } = await tenant.signIn(people.member);
        const person = await call<{ reason?: string }>(
          access_token,
          "GET",
          `/api/resource-grants?${DIRECT}`,
        );
        expect(person.status).toStrictEqual(403);
        expect(person.body.reason).toStrictEqual("user_token");
        expect((await grantsOn(null, DIRECT)).status).toStrictEqual(401);
      });

      function refusedFields(reply: Reply<unknown>): string[] {
        expect(reply.status, JSON.stringify(reply.body)).toStrictEqual(400);
        const { fieldErrors } = reply.body as {
          fieldErrors?: Record<string, string>;
        };
        return Object.keys(fieldErrors ?? {});
      }

      it("refuses a resource type the tenant has not registered, and a resource missing its id", async () => {
        const unregistered = await grantsOn(
          readerToken,
          "type=contract_unregistered&id=direct",
        );
        expect(refusedFields(unregistered)).toStrictEqual(["type"]);
        const missing = await grantsOn(readerToken, "type=contract_document");
        expect(refusedFields(missing)).toStrictEqual(["resource"]);
      });

      it("bounds the type to 64 characters and the id to 255, refusing ASCII control characters and no other", async () => {
        const long = await grantsOn(
          readerToken,
          `type=${"t".repeat(65)}&id=direct`,
        );
        expect(refusedFields(long)).toStrictEqual(["resource"]);
        const longest = await grantsOn(
          readerToken,
          `type=${"t".repeat(64)}&id=direct`,
        );
        expect(refusedFields(longest)).toStrictEqual(["type"]);
        const query = (id: string) =>
          `type=contract_document&id=${encodeURIComponent(id)}`;
        const wide = await grantsOn(readerToken, query("i".repeat(256)));
        expect(refusedFields(wide)).toStrictEqual(["resource"]);
        const widest = await grantsOn(readerToken, query("i".repeat(255)));
        expect(widest.status, JSON.stringify(widest.body)).toStrictEqual(200);
        expect(widest.body.grants).toStrictEqual([]);
        const control = await grantsOn(readerToken, query("tab\there"));
        expect(refusedFields(control)).toStrictEqual(["resource"]);
        const unicode = await grantsOn(readerToken, query("next\u0085line"));
        expect(unicode.status, JSON.stringify(unicode.body)).toStrictEqual(200);
        expect(unicode.body.grants).toStrictEqual([]);
      });
    });
  });
}
