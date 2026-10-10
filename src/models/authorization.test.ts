import { assert, describe, expect, it } from "vitest";
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
    expect(authorization.hasScope("posts:write")).toBeFalsy();

    assert(authorization.can("posts:write"));
    expect(authorization.can("posts:read")).toBeFalsy();

    assert(authorization.hasRole("editor"));
    expect(authorization.hasRole("admin")).toBeFalsy();

    assert(authorization.hasOrgRole("admin"));
    expect(authorization.hasOrgRole("editor")).toBeFalsy();

    assert(authorization.inOrganization());
    assert(authorization.inOrganization("org-1"));
    assert(authorization.inOrganization("acme"));
    expect(authorization.inOrganization("northwind")).toBeFalsy();
  });

  it("treats absent claims as no authorization, never as an error", () => {
    const authorization = authorizationFromClaims({});

    expect(authorization.hasScope("read")).toBeFalsy();
    expect(authorization.can("posts:write")).toBeFalsy();
    expect(authorization.hasRole("editor")).toBeFalsy();
    expect(authorization.hasOrgRole("admin")).toBeFalsy();
    expect(authorization.inOrganization()).toBeFalsy();
    expect(authorization.organization).toStrictEqual(null);
    expect(authorization.roles.size).toStrictEqual(0);
    expect(authorization.permissions.size).toStrictEqual(0);
  });

  it("treats malformed claim shapes as absent", () => {
    const authorization = authorizationFromClaims({
      roles: "editor",
      permissions: [1, null, "posts:write"],
      org_id: 42,
      org_roles: ["admin"],
    });

    expect(authorization.hasRole("editor")).toBeFalsy();
    expect([...authorization.permissions]).toStrictEqual(["posts:write"]);
    expect(authorization.organization).toStrictEqual(null);
    expect(authorization.hasOrgRole("admin")).toBeFalsy();
  });

  it("has no organization without an org_id, whatever else is present", () => {
    const authorization = authorizationFromClaims({
      org_slug: "acme",
      org_roles: ["admin"],
    });
    expect(authorization.organization).toStrictEqual(null);
    expect(authorization.inOrganization("acme")).toBeFalsy();
  });

  it("accepts null and undefined claims", () => {
    expect(authorizationFromClaims(null).inOrganization()).toBeFalsy();
    expect(authorizationFromClaims(undefined).can("posts:write")).toBeFalsy();
  });

  describe("unmet", () => {
    const authorization = authorizationFromClaims(claims);

    it("returns undefined when every condition holds", () => {
      expect(
        authorization.unmet({
          permission: ["posts:write", "billing:read"],
          role: "editor",
          orgRole: "admin",
          organization: "acme",
        }),
      ).toStrictEqual(undefined);
    });

    it("names the first failed check with what it required", () => {
      expect(authorization.unmet({ organization: "northwind" })).toStrictEqual({
        kind: "organization",
        required: "northwind",
      });
      expect(authorization.unmet({ role: ["editor", "owner"] })).toStrictEqual({
        kind: "role",
        required: "owner",
      });
      expect(authorization.unmet({ orgRole: "owner" })).toStrictEqual({
        kind: "orgRole",
        required: "owner",
      });
      expect(authorization.unmet({ permission: "posts:delete" })).toStrictEqual(
        {
          kind: "permission",
          required: "posts:delete",
        },
      );
    });

    it("requires any active organization for organization: true", () => {
      expect(authorization.unmet({ organization: true })).toStrictEqual(
        undefined,
      );
      expect(
        authorizationFromClaims({}).unmet({ organization: true }),
      ).toStrictEqual({
        kind: "organization",
        required: true,
      });
    });

    it("ignores scope conditions — the resource server asserts those", () => {
      expect(authorization.unmet({ scope: "anything" })).toStrictEqual(
        undefined,
      );
    });
  });
});
