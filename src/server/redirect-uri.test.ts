import { assertEquals, assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { isPublicSuffix } from "./public-suffix/mod.ts";
import {
  checkRedirectUriPattern,
  type IsPublicSuffix,
  isRedirectUriPattern,
  matchRedirectUri,
} from "./redirect-uri.ts";

const PATTERN = "https://myapp-*.myorg.deno.net/auth/callback";

function check(pattern: string) {
  return checkRedirectUriPattern(pattern, isPublicSuffix);
}

function match(registered: readonly string[], redirectUri: string) {
  return matchRedirectUri(registered, redirectUri, isPublicSuffix);
}

describe("isRedirectUriPattern", () => {
  it("is true when the redirect URI contains a wildcard", () => {
    assertStrictEquals(isRedirectUriPattern(PATTERN), true);
  });

  it("is false for a literal redirect URI", () => {
    assertStrictEquals(
      isRedirectUriPattern("https://myapp.myorg.deno.net/auth/callback"),
      false,
    );
  });
});

describe("checkRedirectUriPattern", () => {
  it("accepts a wildcard on the leftmost label of an owned subdomain", () => {
    assertStrictEquals(check(PATTERN), null);
  });

  it("accepts a bare wildcard label", () => {
    assertStrictEquals(check("https://*.preview.example.com/cb"), null);
  });

  it("accepts a wildcard between a prefix and a suffix", () => {
    assertStrictEquals(check("https://pr-*-web.myorg.deno.net/cb"), null);
  });

  it("has nothing to check on a literal redirect URI", () => {
    assertStrictEquals(check("http://localhost:8001/auth/callback"), null);
  });

  it("refuses a pattern that is not a parseable absolute URL", () => {
    assertStrictEquals(check("myapp-*.myorg.deno.net/cb")?.rule, "syntax");
  });

  it("refuses a pattern that is not https", () => {
    assertStrictEquals(
      check("http://myapp-*.myorg.deno.net/cb")?.rule,
      "scheme",
    );
  });

  it("refuses more than one wildcard", () => {
    assertStrictEquals(
      check("https://*-*.myorg.deno.net/cb")?.rule,
      "wildcard-count",
    );
    assertStrictEquals(
      check("https://*.myorg.deno.net/*")?.rule,
      "wildcard-count",
    );
  });

  it("refuses a wildcard in the path", () => {
    assertStrictEquals(
      check("https://myapp.myorg.deno.net/*")?.rule,
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the query", () => {
    assertStrictEquals(
      check("https://myapp.myorg.deno.net/cb?next=*")?.rule,
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the fragment", () => {
    assertStrictEquals(
      check("https://myapp.myorg.deno.net/cb#*")?.rule,
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the userinfo", () => {
    assertStrictEquals(
      check("https://*@myapp.myorg.deno.net/cb")?.rule,
      "wildcard-placement",
    );
  });

  it("refuses a wildcard on a label that is not the leftmost", () => {
    assertStrictEquals(
      check("https://myapp.*.deno.net/cb")?.rule,
      "wildcard-placement",
    );
  });

  it("refuses a wildcard whose parent domain is a public suffix", () => {
    for (
      const pattern of [
        "https://*.deno.net/cb",
        "https://myapp-*.deno.net/cb",
        "https://*.vercel.app/cb",
        "https://*.pages.dev/cb",
        "https://*.co.uk/cb",
        "https://*.s3.amazonaws.com/cb",
        "https://*.s3.us-east-1.amazonaws.com/cb",
        "https://*.blob.core.windows.net/cb",
        "https://*.eu-west-1.elasticbeanstalk.com/cb",
        "https://*.blogspot.com/cb",
        "https://*.github.io/cb",
      ]
    ) {
      assertStrictEquals(check(pattern)?.rule, "parent-domain", pattern);
    }
  });

  it("refuses a parent domain whose own children are public suffixes", () => {
    for (
      const pattern of [
        "https://*.r.appspot.com/cb",
        "https://*.compute.amazonaws.com/cb",
        "https://*.compute-1.amazonaws.com/cb",
      ]
    ) {
      assertStrictEquals(check(pattern)?.rule, "parent-domain", pattern);
    }
  });

  it("refuses a public suffix the old platform denylist never named", () => {
    for (
      const pattern of [
        "https://*.user.srcf.net/cb",
        "https://*.abiko.chiba.jp/cb",
        "https://*.centralus.azurestaticapps.net/cb",
        "https://*.cdn.cloudflare.net/cb",
      ]
    ) {
      assertStrictEquals(check(pattern)?.rule, "parent-domain", pattern);
    }
  });

  it("accepts a wildcard directly on a registrable apex", () => {
    assertStrictEquals(check("https://*.example.com/cb"), null);
    assertStrictEquals(check("https://*.example.co.uk/cb"), null);
  });

  it("accepts a wildcard on one tenant's slice of a platform", () => {
    for (
      const pattern of [
        PATTERN,
        "https://*.myorg.deno.net/cb",
        "https://*.myuser.github.io/cb",
        "https://*.mybucket.s3.amazonaws.com/cb",
        "https://*.www.ck/cb",
      ]
    ) {
      assertStrictEquals(check(pattern), null, pattern);
    }
  });

  it("normalizes an internationalized parent domain before checking it", () => {
    assertStrictEquals(check("https://*.xn--p1ai/cb")?.rule, "parent-domain");
    assertStrictEquals(check("https://*.example.xn--p1ai/cb"), null);
  });

  it("treats a trailing dot as the same host rather than an extra label", () => {
    assertStrictEquals(check("https://*.deno.net./cb")?.rule, "parent-domain");
    assertStrictEquals(check("https://myapp-*.myorg.deno.net./cb"), null);
  });

  it("refuses an empty host label", () => {
    for (
      const pattern of [
        "https://*..example.com/cb",
        "https://*.a..example.com/cb",
        "https://*.deno.net../cb",
      ]
    ) {
      assertStrictEquals(check(pattern)?.rule, "syntax", pattern);
    }
  });

  it("refuses every pattern when no public suffix list is supplied", () => {
    for (
      const pattern of [
        PATTERN,
        "https://*.preview.example.com/cb",
        "https://*.deno.net/cb",
      ]
    ) {
      assertStrictEquals(
        checkRedirectUriPattern(pattern)?.rule,
        "parent-domain",
        pattern,
      );
    }
  });

  it("still checks the syntax rules without a public suffix list", () => {
    assertStrictEquals(
      checkRedirectUriPattern("http://*.a.b.com/cb")?.rule,
      "scheme",
    );
    assertStrictEquals(
      checkRedirectUriPattern("https://a.b.com/*")?.rule,
      "wildcard-placement",
    );
    assertStrictEquals(
      checkRedirectUriPattern("https://literal.example.com/cb"),
      null,
    );
  });

  it("uses the supplied list rather than a built-in one", () => {
    const internalOnly: IsPublicSuffix = (domain) => domain === "internal.test";
    assertStrictEquals(
      checkRedirectUriPattern("https://*.internal.test/cb", internalOnly)?.rule,
      "parent-domain",
    );
    assertStrictEquals(
      checkRedirectUriPattern("https://*.deno.net/cb", internalOnly),
      null,
    );
  });

  it("names the violated rule and the reason in the message", () => {
    assertStrictEquals(
      check("http://*.a.example.com/cb")?.message,
      '"http://*.a.example.com/cb" must use https. A wildcard registration ' +
        "covers hosts that do not exist yet, so the authorization code it " +
        "receives has to be protected in transit.",
    );

    assertStrictEquals(
      check("https://*.deno.net/cb")?.message,
      '"https://*.deno.net/cb" wildcards "deno.net", which is a public ' +
        "suffix — anyone can register a name directly under it, obtain a " +
        "neighbouring host, and receive your authorization codes. Put the " +
        "wildcard under a domain your organization registered, for example " +
        "https://myapp-*.myorg.deno.net/callback.",
    );

    assertStrictEquals(
      check("https://*.r.appspot.com/cb")?.message,
      '"https://*.r.appspot.com/cb" wildcards "r.appspot.com", whose ' +
        "subdomains are each a public suffix belonging to a different " +
        "registrant, so a neighbouring host is available to anyone. Put the " +
        "wildcard under a domain your organization registered.",
    );

    assertStrictEquals(
      checkRedirectUriPattern("https://*.preview.example.com/cb")?.message,
      '"https://*.preview.example.com/cb" cannot be registered: this server ' +
        "has no Public Suffix List, so it cannot tell whether " +
        '"preview.example.com" is a namespace your organization controls or ' +
        "one anyone can obtain a host under. Register the callback URLs in " +
        "full, or ask the operator to configure isPublicSuffix.",
    );
  });
});

describe("matchRedirectUri", () => {
  describe("exact matching", () => {
    it("returns the registered entry a request matches exactly", () => {
      const registered = ["https://www.example.com/cb"];
      assertStrictEquals(
        match(registered, "https://www.example.com/cb"),
        "https://www.example.com/cb",
      );
    });

    it("returns undefined when nothing matches", () => {
      assertStrictEquals(
        match(["https://www.example.com/cb"], "https://evil.com/cb"),
        undefined,
      );
    });

    it("still matches a plaintext loopback registration exactly", () => {
      const registered = ["http://localhost:8001/auth/callback"];
      assertStrictEquals(
        match(registered, "http://localhost:8001/auth/callback"),
        "http://localhost:8001/auth/callback",
      );
    });

    it("does not tolerate a differing path, query, or port", () => {
      const registered = ["https://www.example.com/cb"];
      for (
        const requested of [
          "https://www.example.com/cb2",
          "https://www.example.com/cb?x=1",
          "https://www.example.com:8443/cb",
          "https://www.example.com/cb#f",
        ]
      ) {
        assertStrictEquals(match(registered, requested), undefined, requested);
      }
    });

    it("prefers an exact match over a pattern", () => {
      const exact = "https://myapp-a1b2.myorg.deno.net/auth/callback";
      assertStrictEquals(match([PATTERN, exact], exact), exact);
    });

    it("needs no public suffix list for a literal registration", () => {
      const registered = ["https://www.example.com/cb"];
      assertStrictEquals(
        matchRedirectUri(registered, "https://www.example.com/cb"),
        "https://www.example.com/cb",
      );
    });
  });

  describe("loopback port-agnostic matching", () => {
    it("matches an OS-assigned port against a portless 127.0.0.1 registration", () => {
      const registered = ["http://127.0.0.1/callback"];
      assertStrictEquals(
        match(registered, "http://127.0.0.1:53211/callback"),
        "http://127.0.0.1/callback",
      );
    });

    it("matches an OS-assigned port against a registration that named a different port", () => {
      const registered = ["http://127.0.0.1:8080/callback"];
      assertStrictEquals(
        match(registered, "http://127.0.0.1:53211/callback"),
        "http://127.0.0.1:8080/callback",
      );
    });

    it("matches the bracketed IPv6 loopback literal on any port", () => {
      const registered = ["http://[::1]/callback"];
      for (
        const requested of [
          "http://[::1]:53211/callback",
          "http://[::1]/callback",
          "http://[0:0:0:0:0:0:0:1]:9999/callback",
        ]
      ) {
        assertStrictEquals(
          match(registered, requested),
          "http://[::1]/callback",
          requested,
        );
      }
    });

    it("relaxes the port for an https loopback registration too", () => {
      assertStrictEquals(
        match(
          ["https://127.0.0.1/callback"],
          "https://127.0.0.1:7777/callback",
        ),
        "https://127.0.0.1/callback",
      );
    });

    it("relaxes only the port: path, query, and fragment still match exactly", () => {
      const registered = ["http://127.0.0.1/callback"];
      for (
        const requested of [
          "http://127.0.0.1:53211/callback2",
          "http://127.0.0.1:53211/",
          "http://127.0.0.1:53211/callback?code=x",
          "http://127.0.0.1:53211/callback#f",
        ]
      ) {
        assertStrictEquals(match(registered, requested), undefined, requested);
      }
    });

    it("relaxes only the port: scheme, host, and userinfo still match exactly", () => {
      const registered = ["http://127.0.0.1/callback"];
      for (
        const requested of [
          "https://127.0.0.1:53211/callback",
          "http://[::1]:53211/callback",
          "http://127.0.0.2:53211/callback",
          "http://user@127.0.0.1:53211/callback",
        ]
      ) {
        assertStrictEquals(match(registered, requested), undefined, requested);
      }
    });

    it("never relaxes the port for localhost, which is a name and not a literal", () => {
      assertStrictEquals(
        match(["http://localhost/callback"], "http://localhost:53211/callback"),
        undefined,
      );
      assertStrictEquals(
        match(
          ["http://localhost:8001/callback"],
          "http://localhost:9002/callback",
        ),
        undefined,
      );
    });

    it("never relaxes the port for a non-loopback host", () => {
      for (
        const [registration, requested] of [
          ["https://www.example.com/cb", "https://www.example.com:8443/cb"],
          ["https://www.example.com:8443/cb", "https://www.example.com/cb"],
          ["http://10.0.0.1/cb", "http://10.0.0.1:8080/cb"],
          ["http://127.0.0.1.evil.com/cb", "http://127.0.0.1.evil.com:8080/cb"],
        ]
      ) {
        assertStrictEquals(
          match([registration], requested),
          undefined,
          requested,
        );
      }
    });

    it("needs no public suffix list to relax a loopback port", () => {
      assertStrictEquals(
        matchRedirectUri(
          ["http://127.0.0.1/callback"],
          "http://127.0.0.1:53211/callback",
        ),
        "http://127.0.0.1/callback",
      );
    });

    it("prefers an exact registration over a port-relaxed loopback one", () => {
      const registered = [
        "http://127.0.0.1:8080/callback",
        "http://127.0.0.1:53211/callback",
      ];
      assertStrictEquals(
        match(registered, "http://127.0.0.1:53211/callback"),
        "http://127.0.0.1:53211/callback",
      );
    });
  });

  describe("pattern matching", () => {
    it("matches a per-deploy hostname", () => {
      assertStrictEquals(
        match([PATTERN], "https://myapp-a1b2c3.myorg.deno.net/auth/callback"),
        PATTERN,
      );
    });

    it("matches when the wildcard expands to nothing", () => {
      assertStrictEquals(
        match([PATTERN], "https://myapp-.myorg.deno.net/auth/callback"),
        PATTERN,
      );
    });

    it("matches a bare wildcard label", () => {
      const pattern = "https://*.preview.example.com/cb";
      assertStrictEquals(
        match([pattern], "https://pr-42.preview.example.com/cb"),
        pattern,
      );
    });

    it("matches a wildcard on a registrable apex", () => {
      const pattern = "https://*.example.com/cb";
      assertStrictEquals(
        match([pattern], "https://pr-42.example.com/cb"),
        pattern,
      );
    });

    it("requires the wildcard label's prefix and suffix", () => {
      const pattern = "https://pr-*-web.myorg.deno.net/cb";
      assertStrictEquals(
        match([pattern], "https://pr-42-web.myorg.deno.net/cb"),
        pattern,
      );
      assertStrictEquals(
        match([pattern], "https://other-42-web.myorg.deno.net/cb"),
        undefined,
      );
      assertStrictEquals(
        match([pattern], "https://pr-42-api.myorg.deno.net/cb"),
        undefined,
      );
    });

    it("does not let the prefix and suffix overlap", () => {
      const pattern = "https://pr-*-web.myorg.deno.net/cb";
      assertStrictEquals(
        match([pattern], "https://pr--web.myorg.deno.net/cb"),
        pattern,
      );
      assertStrictEquals(
        match([pattern], "https://pr-web.myorg.deno.net/cb"),
        undefined,
      );
    });
  });

  describe("bypass attempts", () => {
    it("refuses a wildcard spanning a dot", () => {
      for (
        const requested of [
          "https://myapp-x.evil.myorg.deno.net/auth/callback",
          "https://myapp-x.evil.deno.net/auth/callback",
          "https://evil.myapp-x.myorg.deno.net/auth/callback",
        ]
      ) {
        assertStrictEquals(match([PATTERN], requested), undefined, requested);
      }
    });

    it("refuses a scheme downgrade", () => {
      assertStrictEquals(
        match([PATTERN], "http://myapp-a1b2.myorg.deno.net/auth/callback"),
        undefined,
      );
    });

    it("never matches a pattern with a wildcard in the path", () => {
      assertStrictEquals(
        match(
          ["https://myapp.myorg.deno.net/*"],
          "https://myapp.myorg.deno.net/anything",
        ),
        undefined,
      );
    });

    it("never matches a pattern on a public suffix", () => {
      assertStrictEquals(
        match(["https://*.deno.net/cb"], "https://attacker.deno.net/cb"),
        undefined,
      );
      assertStrictEquals(
        match(
          ["https://*.r.appspot.com/cb"],
          "https://attacker.r.appspot.com/cb",
        ),
        undefined,
      );
    });

    it("never matches a pattern when no public suffix list is supplied", () => {
      assertStrictEquals(
        matchRedirectUri(
          [PATTERN],
          "https://myapp-a1b2.myorg.deno.net/auth/callback",
        ),
        undefined,
      );
    });

    it("never matches a pattern with more than one wildcard", () => {
      assertStrictEquals(
        match(
          ["https://*-*.myorg.deno.net/cb"],
          "https://a-b.myorg.deno.net/cb",
        ),
        undefined,
      );
    });

    it("never matches a plaintext pattern", () => {
      assertStrictEquals(
        match(["http://*.a.example.com/cb"], "http://x.a.example.com/cb"),
        undefined,
      );
    });

    it("refuses a requested redirect URI that is itself a pattern", () => {
      assertStrictEquals(match([PATTERN], PATTERN), undefined);
      assertStrictEquals(
        match(
          ["https://*.preview.example.com/cb"],
          "https://*.preview.example.com/cb",
        ),
        undefined,
      );
    });

    it("refuses a request whose port, path, or query differs from the pattern", () => {
      for (
        const requested of [
          "https://myapp-a1.myorg.deno.net:8443/auth/callback",
          "https://myapp-a1.myorg.deno.net/auth/callback2",
          "https://myapp-a1.myorg.deno.net/auth/callback?next=https://evil.com",
          "https://myapp-a1.myorg.deno.net/auth/callback#x",
        ]
      ) {
        assertStrictEquals(match([PATTERN], requested), undefined, requested);
      }
    });

    it("refuses a host with a different number of labels", () => {
      assertEquals(
        match([PATTERN], "https://myapp-a1.deno.net/auth/callback"),
        undefined,
      );
    });

    it("refuses a trailing-dot host that would inflate the label count", () => {
      assertStrictEquals(
        match(["https://*.deno.net./cb"], "https://attacker.deno.net./cb"),
        undefined,
      );
      assertStrictEquals(
        match(
          ["https://*.s3.amazonaws.com/cb"],
          "https://attacker-bucket.s3.amazonaws.com/cb",
        ),
        undefined,
      );
    });

    it("treats a trailing dot on the request as the same host", () => {
      assertStrictEquals(
        match([PATTERN], "https://myapp-a1b2.myorg.deno.net./auth/callback"),
        PATTERN,
      );
    });

    it("refuses an empty leftmost label that would satisfy any affix", () => {
      assertStrictEquals(
        match(["https://*.a.example.com/cb"], "https://.a.example.com/cb"),
        undefined,
      );
      assertStrictEquals(
        match(["https://*.a.b.example.com/cb"], "https://x..b.example.com/cb"),
        undefined,
      );
    });

    it("refuses a percent-encoded wildcard in the requested host", () => {
      assertStrictEquals(
        match(
          ["https://a*b.x.example.com/cb"],
          "https://a%2Ab.x.example.com/cb",
        ),
        undefined,
      );
    });

    it("refuses userinfo the pattern did not register", () => {
      assertStrictEquals(
        match([PATTERN], "https://evil@myapp-a1.myorg.deno.net/auth/callback"),
        undefined,
      );
    });
  });
});
