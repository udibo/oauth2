import { assert, assertEquals, assertFalse } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { authorizationFromClaims } from "./authorization.ts";
import { BasicScope } from "./scope.ts";

describe("authorizationFromClaims", () => {
  const claims = {
    roles: ["editor"],
    permissions: ["posts:write", "billing:read"],
    org_id: "org-1",
    org_slug: "acme",
    org_roles: ["admin"],
  };

  it("answers each check from its own claim", () => {
    const authorization = authorizationFromClaims(
      claims,
      new BasicScope("openid posts:read"),
    );

    assert(authorization.hasScope("posts:read"));
    assert(authorization.hasScope("openid posts:read"));
    assertFalse(authorization.hasScope("posts:write"));

    assert(authorization.can("posts:write"));
    assertFalse(authorization.can("posts:read"));

    assert(authorization.hasRole("editor"));
    assertFalse(authorization.hasRole("admin"));

    assert(authorization.hasOrgRole("admin"));
    assertFalse(authorization.hasOrgRole("editor"));

    assert(authorization.inOrganization());
    assert(authorization.inOrganization("org-1"));
    assert(authorization.inOrganization("acme"));
    assertFalse(authorization.inOrganization("northwind"));
  });

  it("treats absent claims as no authorization, never as an error", () => {
    const authorization = authorizationFromClaims({});

    assertFalse(authorization.hasScope("read"));
    assertFalse(authorization.can("posts:write"));
    assertFalse(authorization.hasRole("editor"));
    assertFalse(authorization.hasOrgRole("admin"));
    assertFalse(authorization.inOrganization());
    assertEquals(authorization.organization, null);
    assertEquals(authorization.roles.size, 0);
    assertEquals(authorization.permissions.size, 0);
  });

  it("treats malformed claim shapes as absent", () => {
    const authorization = authorizationFromClaims({
      roles: "editor",
      permissions: [1, null, "posts:write"],
      org_id: 42,
      org_roles: ["admin"],
    });

    assertFalse(authorization.hasRole("editor"));
    assertEquals([...authorization.permissions], ["posts:write"]);
    assertEquals(authorization.organization, null);
    assertFalse(authorization.hasOrgRole("admin"));
  });

  it("has no organization without an org_id, whatever else is present", () => {
    const authorization = authorizationFromClaims({
      org_slug: "acme",
      org_roles: ["admin"],
    });
    assertEquals(authorization.organization, null);
    assertFalse(authorization.inOrganization("acme"));
  });

  it("accepts null and undefined claims", () => {
    assertFalse(authorizationFromClaims(null).inOrganization());
    assertFalse(authorizationFromClaims(undefined).can("posts:write"));
  });

  describe("unmet", () => {
    const authorization = authorizationFromClaims(claims);

    it("returns undefined when every condition holds", () => {
      assertEquals(
        authorization.unmet({
          permission: ["posts:write", "billing:read"],
          role: "editor",
          orgRole: "admin",
          organization: "acme",
        }),
        undefined,
      );
    });

    it("names the first failed check with what it required", () => {
      assertEquals(authorization.unmet({ organization: "northwind" }), {
        kind: "organization",
        required: "northwind",
      });
      assertEquals(authorization.unmet({ role: ["editor", "owner"] }), {
        kind: "role",
        required: "owner",
      });
      assertEquals(authorization.unmet({ orgRole: "owner" }), {
        kind: "orgRole",
        required: "owner",
      });
      assertEquals(authorization.unmet({ permission: "posts:delete" }), {
        kind: "permission",
        required: "posts:delete",
      });
    });

    it("requires any active organization for organization: true", () => {
      assertEquals(authorization.unmet({ organization: true }), undefined);
      assertEquals(authorizationFromClaims({}).unmet({ organization: true }), {
        kind: "organization",
        required: true,
      });
    });

    it("ignores scope conditions — the resource server asserts those", () => {
      assertEquals(authorization.unmet({ scope: "anything" }), undefined);
    });
  });
});
