import { assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isPublicSuffix, publicSuffixListInfo } from "./mod.ts";
import { PUBLIC_SUFFIX_RULES } from "./rules.ts";

const RULE_SHAPE =
  /^!?(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

function assertPublicSuffixes(domains: string[], expected: boolean): void {
  for (const domain of domains) {
    assertStrictEquals(isPublicSuffix(domain), expected, domain);
  }
}

describe("publicSuffixListInfo", () => {
  it("records where the snapshot came from and when", () => {
    assertStrictEquals(
      publicSuffixListInfo.source,
      "https://publicsuffix.org/list/public_suffix_list.dat",
    );
    assertEquals(
      /^\d{4}-\d{2}-\d{2}$/.test(publicSuffixListInfo.retrieved),
      true,
    );
    assertEquals(/^[0-9a-f]{64}$/.test(publicSuffixListInfo.sha256), true);
    assertEquals(publicSuffixListInfo.ruleCount > 5000, true);
  });

  it("counts the rules it actually carries, so a partial regeneration fails", () => {
    assertStrictEquals(
      PUBLIC_SUFFIX_RULES.split("\n").length,
      publicSuffixListInfo.ruleCount,
    );
  });

  it("carries every rule exactly once", () => {
    const rules = PUBLIC_SUFFIX_RULES.split("\n");
    assertStrictEquals(new Set(rules).size, rules.length);
  });

  it("carries only lowercase punycode rules, so a fetched error page fails", () => {
    assertEquals(
      PUBLIC_SUFFIX_RULES.split("\n").filter((rule) => !RULE_SHAPE.test(rule)),
      [],
    );
  });
});

describe("isPublicSuffix", () => {
  it("classifies ICANN registry suffixes", () => {
    assertPublicSuffixes(["com", "net", "co.uk", "in-addr.arpa"], true);
    assertPublicSuffixes(
      ["example.com", "example.co.uk", "www.example.com"],
      false,
    );
  });

  it("classifies private-section platform suffixes", () => {
    assertPublicSuffixes([
      "deno.net",
      "vercel.app",
      "pages.dev",
      "github.io",
      "s3.amazonaws.com",
      "s3.us-east-1.amazonaws.com",
      "blob.core.windows.net",
      "eu-west-1.elasticbeanstalk.com",
    ], true);
  });

  it("treats one tenant's slice of a platform as registrable", () => {
    assertPublicSuffixes(
      ["myorg.deno.net", "myuser.github.io", "mybucket.s3.amazonaws.com"],
      false,
    );
  });

  it("applies wildcard rules", () => {
    assertPublicSuffixes(["ck", "foo.ck", "x.r.appspot.com"], true);
    assertPublicSuffixes(["x.foo.ck", "r.appspot.com"], false);
  });

  it("applies exception rules, which outrank the wildcard they sit under", () => {
    assertPublicSuffixes(["www.ck", "anything.www.ck"], false);
  });

  it("treats an unlisted top-level domain as a public suffix", () => {
    assertStrictEquals(isPublicSuffix("notarealtldanywhere"), true);
    assertStrictEquals(isPublicSuffix("example.notarealtldanywhere"), false);
  });

  it("normalizes case, a trailing dot, and Unicode to punycode", () => {
    assertPublicSuffixes(["CO.UK", "co.uk.", "Deno.NET."], true);
    assertPublicSuffixes(["公司.cn", "xn--55qx5d.cn", "рф", "xn--p1ai"], true);
    assertPublicSuffixes(["example.рф", "example.公司.cn"], false);
  });

  it("reports an unusable host as a public suffix, so callers fail closed", () => {
    assertPublicSuffixes(["", ".", "a..b", ".example.com"], true);
  });
});
