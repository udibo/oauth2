/**
 * Contract test suite for a Udibo tenant's authorization answers: what
 * introspection reports about a signed-in person, and what `POST /api/check`
 * and `POST /api/check/batch` answer.
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

import { assert, assertEquals, assertFalse } from "@std/assert";
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
   * A confidential client the suite signs in with, introspects with and
   * refreshes with. It must be allowed the `refresh_token` grant.
   */
  client: { id: string; secret: string };
  /**
   * How the suite reaches the tenant. Defaults to the global `fetch`; supply
   * one when the tenant's host resolves only through a proxy.
   */
  fetch?: typeof fetch;
  /** Adds a person holding `permissions` tenant-wide, and returns their id. */
  addUser(permissions: string[]): Promise<string>;
  /** Adds an organization and returns its id. */
  addOrganization(): Promise<string>;
  /** Makes a person a member holding `permissions` inside that organization. */
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
   */
  signIn(
    userId: string,
    organizationId?: string,
  ): Promise<TenantContractTokens>;
  /** Releases anything `setup` allocated. */
  cleanup?(): Promise<void> | void;
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
  describe(options.describeName ?? "Udibo tenant contract", () => {
    let tenant: TenantContractFixture;
    let metadata: { token_endpoint: string; introspection_endpoint: string };
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
  });
}
