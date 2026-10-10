import { describe, expect, it } from "vitest";
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
      expect(error.status).toBe(500);
      expect(error.extensions.error).toBe("server_error");
      expect(error.extensions.error_uri).toBe(undefined);
    });

    it("should create error with message", () => {
      const error = new OAuth2Error(400, "test message");
      expect(error.status).toBe(400);
      expect(error.message).toBe("test message");
    });

    it("should create error with options", () => {
      const error = new OAuth2Error(400, "test", {
        extensions: {
          error: "custom_error",
          error_uri: "https://example.com/error",
        },
      });
      expect(error.extensions.error).toBe("custom_error");
      expect(error.extensions.error_uri).toBe("https://example.com/error");
    });
  });

  describe("toJSON", () => {
    it("should include extensions in JSON output", () => {
      const error = new OAuth2Error(400, undefined, {
        extensions: { error: "test_error" },
      });
      const json = error.toJSON();
      expect(json.error).toBe("test_error");
    });

    it("should include error_description extension when set", () => {
      const error = new OAuth2Error(400, "Something went wrong", {
        extensions: {
          error: "test_error",
          error_description: "Something went wrong",
        },
      });
      const json = error.toJSON();
      expect(json.error).toBe("test_error");
      expect(json.error_description).toBe("Something went wrong");
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
      expect(json.error).toBe("test_error");
      expect(json.error_description).toBe("Error");
      expect(json.error_uri).toBe("https://example.com");
    });
  });
});

describe("isOAuth2Error", () => {
  it("should return true for OAuth2Error instances", () => {
    expect(isOAuth2Error(new OAuth2Error(400))).toBe(true);
    expect(isOAuth2Error(new InvalidRequestError())).toBe(true);
    expect(isOAuth2Error(new ServerError())).toBe(true);
  });

  it("should return false for non-OAuth2Error values", () => {
    expect(isOAuth2Error(new Error())).toBe(false);
    expect(isOAuth2Error(null)).toBe(false);
    expect(isOAuth2Error(undefined)).toBe(false);
    expect(isOAuth2Error("error")).toBe(false);
    expect(isOAuth2Error({})).toBe(false);
  });
});

describe("InvalidRequestError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidRequestError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("invalid_request");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InvalidRequestError("missing parameter");
    expect(error.message).toBe("missing parameter");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidRequestError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("InvalidClientError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidClientError();
    expect(error.status).toBe(401);
    expect(error.extensions.error).toBe("invalid_client");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InvalidClientError("client not found");
    expect(error.message).toBe("client not found");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidClientError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("InvalidGrantError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidGrantError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("invalid_grant");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InvalidGrantError("invalid code");
    expect(error.message).toBe("invalid code");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidGrantError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("UnauthorizedClientError", () => {
  it("should have correct defaults", () => {
    const error = new UnauthorizedClientError();
    expect(error.status).toBe(401);
    expect(error.extensions.error).toBe("unauthorized_client");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new UnauthorizedClientError("not authorized");
    expect(error.message).toBe("not authorized");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnauthorizedClientError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("UnsupportedTokenTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedTokenTypeError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("unsupported_token_type");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new UnsupportedTokenTypeError("token type not supported");
    expect(error.message).toBe("token type not supported");
  });
});

describe("UnsupportedGrantTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedGrantTypeError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("unsupported_grant_type");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new UnsupportedGrantTypeError("grant type not supported");
    expect(error.message).toBe("grant type not supported");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnsupportedGrantTypeError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("AccessDeniedError", () => {
  it("should have correct defaults", () => {
    const error = new AccessDeniedError();
    expect(error.status).toBe(401);
    expect(error.extensions.error).toBe("access_denied");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new AccessDeniedError("access denied");
    expect(error.message).toBe("access denied");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new AccessDeniedError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("UnsupportedResponseTypeError", () => {
  it("should have correct defaults", () => {
    const error = new UnsupportedResponseTypeError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("unsupported_response_type");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new UnsupportedResponseTypeError(
      "response type not supported",
    );
    expect(error.message).toBe("response type not supported");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new UnsupportedResponseTypeError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("InvalidScopeError", () => {
  it("should have correct defaults", () => {
    const error = new InvalidScopeError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("invalid_scope");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InvalidScopeError("invalid scope");
    expect(error.message).toBe("invalid scope");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidScopeError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("ServerError", () => {
  it("should have correct defaults", () => {
    const error = new ServerError();
    expect(error.status).toBe(500);
    expect(error.extensions.error).toBe("server_error");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new ServerError("internal error");
    expect(error.message).toBe("internal error");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new ServerError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("TemporarilyUnavailableError", () => {
  it("should have correct defaults", () => {
    const error = new TemporarilyUnavailableError();
    expect(error.status).toBe(503);
    expect(error.extensions.error).toBe("temporarily_unavailable");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new TemporarilyUnavailableError("service unavailable");
    expect(error.message).toBe("service unavailable");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new TemporarilyUnavailableError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("AuthorizationPendingError", () => {
  it("should have correct defaults", () => {
    const error = new AuthorizationPendingError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("authorization_pending");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new AuthorizationPendingError("waiting for user");
    expect(error.message).toBe("waiting for user");
  });
});

describe("SlowDownError", () => {
  it("should have correct defaults", () => {
    const error = new SlowDownError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("slow_down");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new SlowDownError("polling too fast");
    expect(error.message).toBe("polling too fast");
  });
});

describe("ExpiredTokenError", () => {
  it("should have correct defaults", () => {
    const error = new ExpiredTokenError();
    expect(error.status).toBe(400);
    expect(error.extensions.error).toBe("expired_token");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new ExpiredTokenError("device code expired");
    expect(error.message).toBe("device code expired");
  });
});

describe("InvalidTokenError", () => {
  it("should have correct defaults per RFC 6750", () => {
    const error = new InvalidTokenError();
    expect(error.status).toBe(401);
    expect(error.extensions.error).toBe("invalid_token");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InvalidTokenError("token has been revoked");
    expect(error.message).toBe("token has been revoked");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InvalidTokenError("failed", { cause });
    expect(error.cause).toBe(cause);
  });
});

describe("InsufficientScopeError", () => {
  it("should have correct defaults per RFC 6750", () => {
    const error = new InsufficientScopeError();
    expect(error.status).toBe(403);
    expect(error.extensions.error).toBe("insufficient_scope");
    expect(isOAuth2Error(error)).toBe(true);
  });

  it("should accept message", () => {
    const error = new InsufficientScopeError("scope required");
    expect(error.message).toBe("scope required");
  });

  it("should accept cause", () => {
    const cause = new Error("original error");
    const error = new InsufficientScopeError("failed", { cause });
    expect(error.cause).toBe(cause);
  });

  it("should store required scope", () => {
    const error = new InsufficientScopeError("need admin scope", {
      extensions: { requiredScope: "admin" },
    });
    expect(error.extensions.requiredScope).toBe("admin");
  });

  it("should handle multiple required scopes", () => {
    const error = new InsufficientScopeError("need more permissions", {
      extensions: { requiredScope: "read write admin" },
    });
    expect(error.extensions.requiredScope).toBe("read write admin");
  });
});
