import { describe, expect, it } from "vitest";
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
    expect(isRedirectUriPattern(PATTERN)).toBe(true);
  });

  it("is false for a literal redirect URI", () => {
    expect(
      isRedirectUriPattern("https://myapp.myorg.deno.net/auth/callback"),
    ).toBe(false);
  });
});

describe("checkRedirectUriPattern", () => {
  it("accepts a wildcard on the leftmost label of an owned subdomain", () => {
    expect(check(PATTERN)).toBe(null);
  });

  it("accepts a bare wildcard label", () => {
    expect(check("https://*.preview.example.com/cb")).toBe(null);
  });

  it("accepts a wildcard between a prefix and a suffix", () => {
    expect(check("https://pr-*-web.myorg.deno.net/cb")).toBe(null);
  });

  it("has nothing to check on a literal redirect URI", () => {
    expect(check("http://localhost:8001/auth/callback")).toBe(null);
  });

  it("refuses a pattern that is not a parseable absolute URL", () => {
    expect(check("myapp-*.myorg.deno.net/cb")?.rule).toBe("syntax");
  });

  it("refuses a pattern that is not https", () => {
    expect(check("http://myapp-*.myorg.deno.net/cb")?.rule).toBe("scheme");
  });

  it("refuses more than one wildcard", () => {
    expect(check("https://*-*.myorg.deno.net/cb")?.rule).toBe("wildcard-count");
    expect(check("https://*.myorg.deno.net/*")?.rule).toBe("wildcard-count");
  });

  it("refuses a wildcard in the path", () => {
    expect(check("https://myapp.myorg.deno.net/*")?.rule).toBe(
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the query", () => {
    expect(check("https://myapp.myorg.deno.net/cb?next=*")?.rule).toBe(
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the fragment", () => {
    expect(check("https://myapp.myorg.deno.net/cb#*")?.rule).toBe(
      "wildcard-placement",
    );
  });

  it("refuses a wildcard in the userinfo", () => {
    expect(check("https://*@myapp.myorg.deno.net/cb")?.rule).toBe(
      "wildcard-placement",
    );
  });

  it("refuses a wildcard on a label that is not the leftmost", () => {
    expect(check("https://myapp.*.deno.net/cb")?.rule).toBe(
      "wildcard-placement",
    );
  });

  it("refuses a wildcard whose parent domain is a public suffix", () => {
    for (const pattern of [
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
    ]) {
      expect(check(pattern)?.rule, pattern).toBe("parent-domain");
    }
  });

  it("refuses a parent domain whose own children are public suffixes", () => {
    for (const pattern of [
      "https://*.r.appspot.com/cb",
      "https://*.compute.amazonaws.com/cb",
      "https://*.compute-1.amazonaws.com/cb",
    ]) {
      expect(check(pattern)?.rule, pattern).toBe("parent-domain");
    }
  });

  it("refuses a public suffix the old platform denylist never named", () => {
    for (const pattern of [
      "https://*.user.srcf.net/cb",
      "https://*.abiko.chiba.jp/cb",
      "https://*.centralus.azurestaticapps.net/cb",
      "https://*.cdn.cloudflare.net/cb",
    ]) {
      expect(check(pattern)?.rule, pattern).toBe("parent-domain");
    }
  });

  it("accepts a wildcard directly on a registrable apex", () => {
    expect(check("https://*.example.com/cb")).toBe(null);
    expect(check("https://*.example.co.uk/cb")).toBe(null);
  });

  it("accepts a wildcard on one tenant's slice of a platform", () => {
    for (const pattern of [
      PATTERN,
      "https://*.myorg.deno.net/cb",
      "https://*.myuser.github.io/cb",
      "https://*.mybucket.s3.amazonaws.com/cb",
      "https://*.www.ck/cb",
    ]) {
      expect(check(pattern), pattern).toBe(null);
    }
  });

  it("normalizes an internationalized parent domain before checking it", () => {
    expect(check("https://*.xn--p1ai/cb")?.rule).toBe("parent-domain");
    expect(check("https://*.example.xn--p1ai/cb")).toBe(null);
  });

  it("treats a trailing dot as the same host rather than an extra label", () => {
    expect(check("https://*.deno.net./cb")?.rule).toBe("parent-domain");
    expect(check("https://myapp-*.myorg.deno.net./cb")).toBe(null);
  });

  it("refuses an empty host label", () => {
    for (const pattern of [
      "https://*..example.com/cb",
      "https://*.a..example.com/cb",
      "https://*.deno.net../cb",
    ]) {
      expect(check(pattern)?.rule, pattern).toBe("syntax");
    }
  });

  it("refuses every pattern when no public suffix list is supplied", () => {
    for (const pattern of [
      PATTERN,
      "https://*.preview.example.com/cb",
      "https://*.deno.net/cb",
    ]) {
      expect(checkRedirectUriPattern(pattern)?.rule, pattern).toBe(
        "parent-domain",
      );
    }
  });

  it("still checks the syntax rules without a public suffix list", () => {
    expect(checkRedirectUriPattern("http://*.a.b.com/cb")?.rule).toBe("scheme");
    expect(checkRedirectUriPattern("https://a.b.com/*")?.rule).toBe(
      "wildcard-placement",
    );
    expect(checkRedirectUriPattern("https://literal.example.com/cb")).toBe(
      null,
    );
  });

  it("uses the supplied list rather than a built-in one", () => {
    const internalOnly: IsPublicSuffix = (domain) => domain === "internal.test";
    expect(
      checkRedirectUriPattern("https://*.internal.test/cb", internalOnly)?.rule,
    ).toBe("parent-domain");
    expect(checkRedirectUriPattern("https://*.deno.net/cb", internalOnly)).toBe(
      null,
    );
  });

  it("names the violated rule and the reason in the message", () => {
    expect(check("http://*.a.example.com/cb")?.message).toBe(
      '"http://*.a.example.com/cb" must use https. A wildcard registration ' +
        "covers hosts that do not exist yet, so the authorization code it " +
        "receives has to be protected in transit.",
    );

    expect(check("https://*.deno.net/cb")?.message).toBe(
      '"https://*.deno.net/cb" wildcards "deno.net", which is a public ' +
        "suffix — anyone can register a name directly under it, obtain a " +
        "neighbouring host, and receive your authorization codes. Put the " +
        "wildcard under a domain your organization registered, for example " +
        "https://myapp-*.myorg.deno.net/callback.",
    );

    expect(check("https://*.r.appspot.com/cb")?.message).toBe(
      '"https://*.r.appspot.com/cb" wildcards "r.appspot.com", whose ' +
        "subdomains are each a public suffix belonging to a different " +
        "registrant, so a neighbouring host is available to anyone. Put the " +
        "wildcard under a domain your organization registered.",
    );

    expect(
      checkRedirectUriPattern("https://*.preview.example.com/cb")?.message,
    ).toBe(
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
      expect(match(registered, "https://www.example.com/cb")).toBe(
        "https://www.example.com/cb",
      );
    });

    it("returns undefined when nothing matches", () => {
      expect(match(["https://www.example.com/cb"], "https://evil.com/cb")).toBe(
        undefined,
      );
    });

    it("still matches a plaintext loopback registration exactly", () => {
      const registered = ["http://localhost:8001/auth/callback"];
      expect(match(registered, "http://localhost:8001/auth/callback")).toBe(
        "http://localhost:8001/auth/callback",
      );
    });

    it("does not tolerate a differing path, query, or port", () => {
      const registered = ["https://www.example.com/cb"];
      for (const requested of [
        "https://www.example.com/cb2",
        "https://www.example.com/cb?x=1",
        "https://www.example.com:8443/cb",
        "https://www.example.com/cb#f",
      ]) {
        expect(match(registered, requested), requested).toBe(undefined);
      }
    });

    it("prefers an exact match over a pattern", () => {
      const exact = "https://myapp-a1b2.myorg.deno.net/auth/callback";
      expect(match([PATTERN, exact], exact)).toBe(exact);
    });

    it("needs no public suffix list for a literal registration", () => {
      const registered = ["https://www.example.com/cb"];
      expect(matchRedirectUri(registered, "https://www.example.com/cb")).toBe(
        "https://www.example.com/cb",
      );
    });
  });

  describe("loopback port-agnostic matching", () => {
    it("matches an OS-assigned port against a portless 127.0.0.1 registration", () => {
      const registered = ["http://127.0.0.1/callback"];
      expect(match(registered, "http://127.0.0.1:53211/callback")).toBe(
        "http://127.0.0.1/callback",
      );
    });

    it("matches an OS-assigned port against a registration that named a different port", () => {
      const registered = ["http://127.0.0.1:8080/callback"];
      expect(match(registered, "http://127.0.0.1:53211/callback")).toBe(
        "http://127.0.0.1:8080/callback",
      );
    });

    it("matches the bracketed IPv6 loopback literal on any port", () => {
      const registered = ["http://[::1]/callback"];
      for (const requested of [
        "http://[::1]:53211/callback",
        "http://[::1]/callback",
        "http://[0:0:0:0:0:0:0:1]:9999/callback",
      ]) {
        expect(match(registered, requested), requested).toBe(
          "http://[::1]/callback",
        );
      }
    });

    it("relaxes the port for an https loopback registration too", () => {
      expect(
        match(
          ["https://127.0.0.1/callback"],
          "https://127.0.0.1:7777/callback",
        ),
      ).toBe("https://127.0.0.1/callback");
    });

    it("relaxes only the port: path, query, and fragment still match exactly", () => {
      const registered = ["http://127.0.0.1/callback"];
      for (const requested of [
        "http://127.0.0.1:53211/callback2",
        "http://127.0.0.1:53211/",
        "http://127.0.0.1:53211/callback?code=x",
        "http://127.0.0.1:53211/callback#f",
      ]) {
        expect(match(registered, requested), requested).toBe(undefined);
      }
    });

    it("relaxes only the port: scheme, host, and userinfo still match exactly", () => {
      const registered = ["http://127.0.0.1/callback"];
      for (const requested of [
        "https://127.0.0.1:53211/callback",
        "http://[::1]:53211/callback",
        "http://127.0.0.2:53211/callback",
        "http://user@127.0.0.1:53211/callback",
      ]) {
        expect(match(registered, requested), requested).toBe(undefined);
      }
    });

    it("never relaxes the port for localhost, which is a name and not a literal", () => {
      expect(
        match(["http://localhost/callback"], "http://localhost:53211/callback"),
      ).toBe(undefined);
      expect(
        match(
          ["http://localhost:8001/callback"],
          "http://localhost:9002/callback",
        ),
      ).toBe(undefined);
    });

    it("never relaxes the port for a non-loopback host", () => {
      for (const [registration, requested] of [
        ["https://www.example.com/cb", "https://www.example.com:8443/cb"],
        ["https://www.example.com:8443/cb", "https://www.example.com/cb"],
        ["http://10.0.0.1/cb", "http://10.0.0.1:8080/cb"],
        ["http://127.0.0.1.evil.com/cb", "http://127.0.0.1.evil.com:8080/cb"],
      ]) {
        expect(match([registration], requested), requested).toBe(undefined);
      }
    });

    it("needs no public suffix list to relax a loopback port", () => {
      expect(
        matchRedirectUri(
          ["http://127.0.0.1/callback"],
          "http://127.0.0.1:53211/callback",
        ),
      ).toBe("http://127.0.0.1/callback");
    });

    it("prefers an exact registration over a port-relaxed loopback one", () => {
      const registered = [
        "http://127.0.0.1:8080/callback",
        "http://127.0.0.1:53211/callback",
      ];
      expect(match(registered, "http://127.0.0.1:53211/callback")).toBe(
        "http://127.0.0.1:53211/callback",
      );
    });
  });

  describe("pattern matching", () => {
    it("matches a per-deploy hostname", () => {
      expect(
        match([PATTERN], "https://myapp-a1b2c3.myorg.deno.net/auth/callback"),
      ).toBe(PATTERN);
    });

    it("matches when the wildcard expands to nothing", () => {
      expect(
        match([PATTERN], "https://myapp-.myorg.deno.net/auth/callback"),
      ).toBe(PATTERN);
    });

    it("matches a bare wildcard label", () => {
      const pattern = "https://*.preview.example.com/cb";
      expect(match([pattern], "https://pr-42.preview.example.com/cb")).toBe(
        pattern,
      );
    });

    it("matches a wildcard on a registrable apex", () => {
      const pattern = "https://*.example.com/cb";
      expect(match([pattern], "https://pr-42.example.com/cb")).toBe(pattern);
    });

    it("requires the wildcard label's prefix and suffix", () => {
      const pattern = "https://pr-*-web.myorg.deno.net/cb";
      expect(match([pattern], "https://pr-42-web.myorg.deno.net/cb")).toBe(
        pattern,
      );
      expect(match([pattern], "https://other-42-web.myorg.deno.net/cb")).toBe(
        undefined,
      );
      expect(match([pattern], "https://pr-42-api.myorg.deno.net/cb")).toBe(
        undefined,
      );
    });

    it("does not let the prefix and suffix overlap", () => {
      const pattern = "https://pr-*-web.myorg.deno.net/cb";
      expect(match([pattern], "https://pr--web.myorg.deno.net/cb")).toBe(
        pattern,
      );
      expect(match([pattern], "https://pr-web.myorg.deno.net/cb")).toBe(
        undefined,
      );
    });
  });

  describe("bypass attempts", () => {
    it("refuses a wildcard spanning a dot", () => {
      for (const requested of [
        "https://myapp-x.evil.myorg.deno.net/auth/callback",
        "https://myapp-x.evil.deno.net/auth/callback",
        "https://evil.myapp-x.myorg.deno.net/auth/callback",
      ]) {
        expect(match([PATTERN], requested), requested).toBe(undefined);
      }
    });

    it("refuses a scheme downgrade", () => {
      expect(
        match([PATTERN], "http://myapp-a1b2.myorg.deno.net/auth/callback"),
      ).toBe(undefined);
    });

    it("never matches a pattern with a wildcard in the path", () => {
      expect(
        match(
          ["https://myapp.myorg.deno.net/*"],
          "https://myapp.myorg.deno.net/anything",
        ),
      ).toBe(undefined);
    });

    it("never matches a pattern on a public suffix", () => {
      expect(
        match(["https://*.deno.net/cb"], "https://attacker.deno.net/cb"),
      ).toBe(undefined);
      expect(
        match(
          ["https://*.r.appspot.com/cb"],
          "https://attacker.r.appspot.com/cb",
        ),
      ).toBe(undefined);
    });

    it("never matches a pattern when no public suffix list is supplied", () => {
      expect(
        matchRedirectUri(
          [PATTERN],
          "https://myapp-a1b2.myorg.deno.net/auth/callback",
        ),
      ).toBe(undefined);
    });

    it("never matches a pattern with more than one wildcard", () => {
      expect(
        match(
          ["https://*-*.myorg.deno.net/cb"],
          "https://a-b.myorg.deno.net/cb",
        ),
      ).toBe(undefined);
    });

    it("never matches a plaintext pattern", () => {
      expect(
        match(["http://*.a.example.com/cb"], "http://x.a.example.com/cb"),
      ).toBe(undefined);
    });

    it("refuses a requested redirect URI that is itself a pattern", () => {
      expect(match([PATTERN], PATTERN)).toBe(undefined);
      expect(
        match(
          ["https://*.preview.example.com/cb"],
          "https://*.preview.example.com/cb",
        ),
      ).toBe(undefined);
    });

    it("refuses a request whose port, path, or query differs from the pattern", () => {
      for (const requested of [
        "https://myapp-a1.myorg.deno.net:8443/auth/callback",
        "https://myapp-a1.myorg.deno.net/auth/callback2",
        "https://myapp-a1.myorg.deno.net/auth/callback?next=https://evil.com",
        "https://myapp-a1.myorg.deno.net/auth/callback#x",
      ]) {
        expect(match([PATTERN], requested), requested).toBe(undefined);
      }
    });

    it("refuses a host with a different number of labels", () => {
      expect(
        match([PATTERN], "https://myapp-a1.deno.net/auth/callback"),
      ).toStrictEqual(undefined);
    });

    it("refuses a trailing-dot host that would inflate the label count", () => {
      expect(
        match(["https://*.deno.net./cb"], "https://attacker.deno.net./cb"),
      ).toBe(undefined);
      expect(
        match(
          ["https://*.s3.amazonaws.com/cb"],
          "https://attacker-bucket.s3.amazonaws.com/cb",
        ),
      ).toBe(undefined);
    });

    it("treats a trailing dot on the request as the same host", () => {
      expect(
        match([PATTERN], "https://myapp-a1b2.myorg.deno.net./auth/callback"),
      ).toBe(PATTERN);
    });

    it("refuses an empty leftmost label that would satisfy any affix", () => {
      expect(
        match(["https://*.a.example.com/cb"], "https://.a.example.com/cb"),
      ).toBe(undefined);
      expect(
        match(["https://*.a.b.example.com/cb"], "https://x..b.example.com/cb"),
      ).toBe(undefined);
    });

    it("refuses a percent-encoded wildcard in the requested host", () => {
      expect(
        match(
          ["https://a*b.x.example.com/cb"],
          "https://a%2Ab.x.example.com/cb",
        ),
      ).toBe(undefined);
    });

    it("refuses userinfo the pattern did not register", () => {
      expect(
        match([PATTERN], "https://evil@myapp-a1.myorg.deno.net/auth/callback"),
      ).toBe(undefined);
    });
  });
});
