import { assertStrictEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import {
  AccessDeniedError,
  AuthorizationPendingError,
  ExpiredTokenError,
  InsufficientScopeError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  isOAuth2Error,
  OAuth2Error,
  ServerError,
  SlowDownError,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
  UnsupportedResponseTypeError,
  UnsupportedTokenTypeError,
} from "./errors.ts";

describe("OAuth2Error", () => {
  describe("constructor", () => {
    it("should create error with default values", () => {
      const error = new OAuth2Error(500);
      assertStrictEquals(error.status, 500);
      assertStrictEquals(error.extensions.error, "server_error");
      assertStrictEquals(error.extensions.error_uri, undefined);
    });

    it("should create error with message", () => {
      const error = new OAuth2Error(400, "test message");
      assertStrictEquals(error.status, 400);
      assertStrictEquals(error.message, "test message");
    });

    it("should create error with options", () => {
      const error = new OAuth2Error(400, "test", {
        extensions: {
          error: "custom_error",
          error_uri: "https://example.com/error",
        },
      });
      assertStrictEquals(error.extensions.error, "custom_error");
      assertStrictEquals(
        error.extensions.error_uri,
        "https://example.com/error",
      );
    });
  });

  describe("toJSON", () => {
    it("should include extensions in JSON output", () => {
      const error = new OAuth2Error(400, undefined, {
        extensions: { error: "test_error" },
      });
      const json = error.toJSON();
      assertStrictEquals(json.error, "test_error");
    });

    it("should include error_description extension when set", () => {
      const error = new OAuth2Error(400, "Something went wrong", {
        extensions: {
          error: "test_error",
          error_description: "Something went wrong",
        },
      });
      const json = error.toJSON();
      assertStrictEquals(json.error, "test_error");
      assertStrictEquals(json.error_description, "Something went wrong");
    });

    it("should include error_uri extension when set", () => {
      const error = new OAuth2Error(400, "Error", {
        extensions: {
          error: "test_error",
          error_description: "Error",
          error_uri: "https://example.com",
        },
      });
      const json = error.toJSON();
      assertStrictEquals(json.error, "test_error");
      assertStrictEquals(json.error_description, "Error");
      assertStrictEquals(json.error_uri, "https://example.com");
    });
  });
});

describe("isOAuth2Error", () => {
  it("should return true for OAuth2Error instances", () => {
    assertStrictEquals(isOAuth2Error(new OAuth2Error(400)), true);
    assertStrictEquals(isOAuth2Error(new InvalidRequestError()), true);
    assertStrictEquals(isOAuth2Error(new ServerError()), true);
  });

  it("should return false for non-OAuth2Error values", () => {
    assertStrictEquals(isOAuth2Error(new Error()), false);
    assertStrictEquals(isOAuth2Error(null), false);
    assertStrictEquals(isOAuth2Error(undefined), false);
    assertStrictEquals(isOAuth2Error("error"), false);
    assertStrictEquals(isOAuth2Error({}), false);
  });
});

describe("InvalidRequestError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidRequestError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "invalid_request");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InvalidRequestError("missing parameter");
    assertStrictEquals(error.message, "missing parameter");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidRequestError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("InvalidClientError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidClientError();
    assertStrictEquals(error.status, 401);
    assertStrictEquals(error.extensions.error, "invalid_client");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InvalidClientError("client not found");
    assertStrictEquals(error.message, "client not found");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidClientError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("InvalidGrantError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidGrantError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "invalid_grant");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InvalidGrantError("invalid code");
    assertStrictEquals(error.message, "invalid code");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidGrantError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("UnauthorizedClientError", () => {
  it("should have correct defaults", () => {
    const error = new UnauthorizedClientError();
    assertStrictEquals(error.status, 401);
    assertStrictEquals(error.extensions.error, "unauthorized_client");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new UnauthorizedClientError("not authorized");
    assertStrictEquals(error.message, "not authorized");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnauthorizedClientError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("UnsupportedTokenTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedTokenTypeError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "unsupported_token_type");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new UnsupportedTokenTypeError("token type not supported");
    assertStrictEquals(error.message, "token type not supported");
  });
});

describe("UnsupportedGrantTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedGrantTypeError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "unsupported_grant_type");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new UnsupportedGrantTypeError("grant type not supported");
    assertStrictEquals(error.message, "grant type not supported");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnsupportedGrantTypeError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("AccessDeniedError", () => {
  it("should have correct defaults", () => {
    const error = new AccessDeniedError();
    assertStrictEquals(error.status, 401);
    assertStrictEquals(error.extensions.error, "access_denied");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new AccessDeniedError("access denied");
    assertStrictEquals(error.message, "access denied");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new AccessDeniedError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("UnsupportedResponseTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedResponseTypeError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(
      error.extensions.error,
      "unsupported_response_type",
    );
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new UnsupportedResponseTypeError(
      "response type not supported",
    );
    assertStrictEquals(error.message, "response type not supported");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnsupportedResponseTypeError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("InvalidScopeError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidScopeError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "invalid_scope");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InvalidScopeError("invalid scope");
    assertStrictEquals(error.message, "invalid scope");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidScopeError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("ServerError", () => {
  it("should have correct defaults", () => {
    const error = new ServerError();
    assertStrictEquals(error.status, 500);
    assertStrictEquals(error.extensions.error, "server_error");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new ServerError("internal error");
    assertStrictEquals(error.message, "internal error");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new ServerError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("TemporarilyUnavailableError", () => {
  it("should have correct defaults", () => {
    const error = new TemporarilyUnavailableError();
    assertStrictEquals(error.status, 503);
    assertStrictEquals(
      error.extensions.error,
      "temporarily_unavailable",
    );
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new TemporarilyUnavailableError("service unavailable");
    assertStrictEquals(error.message, "service unavailable");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new TemporarilyUnavailableError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("AuthorizationPendingError", () => {
  it("should have correct defaults", () => {
    const error = new AuthorizationPendingError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(
      error.extensions.error,
      "authorization_pending",
    );
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new AuthorizationPendingError("waiting for user");
    assertStrictEquals(error.message, "waiting for user");
  });
});

describe("SlowDownError", () => {
  it("should have correct defaults", () => {
    const error = new SlowDownError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "slow_down");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new SlowDownError("polling too fast");
    assertStrictEquals(error.message, "polling too fast");
  });
});

describe("ExpiredTokenError", () => {
  it("should have correct defaults", () => {
    const error = new ExpiredTokenError();
    assertStrictEquals(error.status, 400);
    assertStrictEquals(error.extensions.error, "expired_token");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new ExpiredTokenError("device code expired");
    assertStrictEquals(error.message, "device code expired");
  });
});

describe("InvalidTokenError", () => {
  it("should have correct defaults per RFC 6750", () => {
    const error = new InvalidTokenError();
    assertStrictEquals(error.status, 401);
    assertStrictEquals(error.extensions.error, "invalid_token");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InvalidTokenError("token has been revoked");
    assertStrictEquals(error.message, "token has been revoked");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidTokenError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });
});

describe("InsufficientScopeError", () => {
  it("should have correct defaults per RFC 6750", () => {
    const error = new InsufficientScopeError();
    assertStrictEquals(error.status, 403);
    assertStrictEquals(error.extensions.error, "insufficient_scope");
    assertStrictEquals(isOAuth2Error(error), true);
  });

  it("should accept message", () => {
    const error = new InsufficientScopeError("scope required");
    assertStrictEquals(error.message, "scope required");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InsufficientScopeError("failed", { cause });
    assertStrictEquals(error.cause, cause);
  });

  it("should store required scope", () => {
    const error = new InsufficientScopeError("need admin scope", {
      extensions: { requiredScope: "admin" },
    });
    assertStrictEquals(error.extensions.requiredScope, "admin");
  });

  it("should handle multiple required scopes", () => {
    const error = new InsufficientScopeError("need more permissions", {
      extensions: { requiredScope: "read write admin" },
    });
    assertStrictEquals(
      error.extensions.requiredScope,
      "read write admin",
    );
  });
});
