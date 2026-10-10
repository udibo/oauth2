import { describe, expect, it } from "vitest";
import { thrown } from "../_test_assert.ts";
import { InvalidScopeError } from "../errors.ts";
import { BasicScope, NQCHAR, SCOPE, SCOPE_TOKEN } from "./scope.ts";

describe("NQCHAR", () => {
  it("should match valid NQCHAR characters", () => {
    expect(NQCHAR.test("!")).toBe(true);
    expect(NQCHAR.test("#")).toBe(true);
    expect(NQCHAR.test("A")).toBe(true);
    expect(NQCHAR.test("z")).toBe(true);
    expect(NQCHAR.test("~")).toBe(true);
  });

  it("should not match invalid characters", () => {
    expect(NQCHAR.test('"')).toBe(false);
    expect(NQCHAR.test("\\")).toBe(false);
    expect(NQCHAR.test(" ")).toBe(false);
  });
});

describe("SCOPE", () => {
  it("should match empty string", () => {
    expect(SCOPE.test("")).toBe(true);
  });

  it("should match single token", () => {
    expect(SCOPE.test("a")).toBe(true);
    expect(SCOPE.test("read")).toBe(true);
  });

  it("should match multiple space-separated tokens", () => {
    expect(SCOPE.test("a b a c")).toBe(true);
    expect(SCOPE.test("read write")).toBe(true);
    expect(SCOPE.test("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~")).toBe(true);
  });

  it("should not match leading/trailing spaces", () => {
    expect(SCOPE.test(" ")).toBe(false);
    expect(SCOPE.test(" a")).toBe(false);
    expect(SCOPE.test("a ")).toBe(false);
  });

  it("should not match multiple spaces between tokens", () => {
    expect(SCOPE.test("a  b")).toBe(false);
  });

  it("should not match invalid characters", () => {
    expect(SCOPE.test('"')).toBe(false);
    expect(SCOPE.test('a"b')).toBe(false);
    expect(SCOPE.test('a b"c a d')).toBe(false);
    expect(SCOPE.test("\\")).toBe(false);
    expect(SCOPE.test("a\\b")).toBe(false);
    expect(SCOPE.test("a b\\c a d")).toBe(false);
  });
});

describe("SCOPE_TOKEN", () => {
  it("should return null for empty string", () => {
    expect("".match(SCOPE_TOKEN)).toStrictEqual(null);
  });

  it("should extract single token", () => {
    expect("a".match(SCOPE_TOKEN)).toStrictEqual(["a"]);
  });

  it("should extract multiple tokens", () => {
    expect("a b a c".match(SCOPE_TOKEN)).toStrictEqual(["a", "b", "a", "c"]);
  });

  it("should extract complex tokens", () => {
    expect(
      "!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~".match(SCOPE_TOKEN),
    ).toStrictEqual(["!#0A[]a~", "!#1B[]b~", "!#0A[]a~", "!#2C[]c~"]);
  });
});

describe("BasicScope", () => {
  describe("constructor", () => {
    it("should accept valid scope strings", () => {
      new BasicScope("a");
      new BasicScope("a b a c");
      new BasicScope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
    });

    it("should accept empty string", () => {
      const scope = new BasicScope("");
      expect(scope.toString()).toBe("");
    });

    it("should throw InvalidBasicScopeError for invalid scope", () => {
      thrown(() => new BasicScope(" "), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope(" a"), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope("a "), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope("a  b"), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope('"'), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope('a"b'), InvalidScopeError, "invalid scope");
      thrown(
        () => new BasicScope('a b"ca d'),
        InvalidScopeError,
        "invalid scope",
      );
      thrown(() => new BasicScope("\\"), InvalidScopeError, "invalid scope");
      thrown(() => new BasicScope("a\\b"), InvalidScopeError, "invalid scope");
      thrown(
        () => new BasicScope("a b\\c a d"),
        InvalidScopeError,
        "invalid scope",
      );
    });
  });

  describe("toString", () => {
    it("should return deduplicated space-separated tokens", () => {
      let scope = new BasicScope("a");
      expect(scope.toString()).toBe("a");

      scope = new BasicScope("a b a c");
      expect(scope.toString()).toBe("a b c");

      scope = new BasicScope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
      expect(scope.toString()).toBe("!#0A[]a~ !#1B[]b~ !#2C[]c~");
    });

    it("should be idempotent", () => {
      const scope = new BasicScope("a b c");
      expect(scope.toString()).toBe("a b c");
      expect(scope.toString()).toBe("a b c");
    });
  });

  describe("toJSON", () => {
    it("should return same as toString", () => {
      let scope = new BasicScope("a");
      expect(scope.toJSON()).toBe("a");

      scope = new BasicScope("a b a c");
      expect(scope.toJSON()).toBe("a b c");

      scope = new BasicScope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
      expect(scope.toJSON()).toBe("!#0A[]a~ !#1B[]b~ !#2C[]c~");
    });
  });

  describe("from", () => {
    it("should create from string", () => {
      expect(BasicScope.from("a").toString()).toBe("a");
      expect(BasicScope.from("a b a c").toString()).toBe("a b c");
    });

    it("should create copy from BasicScope", () => {
      const original = new BasicScope("a b c");
      const copy = BasicScope.from(original);
      expect(copy.toString()).toBe("a b c");
      copy.add("d");
      expect(original.toString()).toBe("a b c");
      expect(copy.toString()).toBe("a b c d");
    });
  });

  describe("has", () => {
    it("should return true for contained tokens", () => {
      const scope = new BasicScope("a b c");
      expect(scope.has("a")).toBe(true);
      expect(scope.has("b")).toBe(true);
      expect(scope.has("c")).toBe(true);
    });

    it("should return false for non-contained tokens", () => {
      const scope = new BasicScope("a b c");
      expect(scope.has("d")).toBe(false);
    });

    it("should check multiple tokens", () => {
      const scope = new BasicScope("a b c");
      expect(scope.has("a b")).toBe(true);
      expect(scope.has("b c")).toBe(true);
      expect(scope.has("a b c")).toBe(true);
      expect(scope.has("c d")).toBe(false);
      expect(scope.has("d a")).toBe(false);
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a b c");
      expect(scope.has(new BasicScope("a"))).toBe(true);
      expect(scope.has(new BasicScope("a b"))).toBe(true);
      expect(scope.has(new BasicScope("d"))).toBe(false);
    });
  });

  describe("add", () => {
    it("should add tokens to scope", () => {
      const scope = new BasicScope();
      expect(scope.add("a")).toBe(scope);
      expect(scope.toString()).toBe("a");
      expect(scope.add("b")).toBe(scope);
      expect(scope.toString()).toBe("a b");
    });

    it("should handle duplicates", () => {
      const scope = new BasicScope("a b");
      scope.add("b c");
      expect(scope.toString()).toBe("a b c");
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a");
      scope.add(new BasicScope("b c"));
      expect(scope.toString()).toBe("a b c");
    });

    it("should return this for chaining", () => {
      const scope = new BasicScope();
      scope.add("a").add("b").add("c");
      expect(scope.toString()).toBe("a b c");
    });
  });

  describe("remove", () => {
    it("should remove tokens from scope", () => {
      const scope = new BasicScope("a b c d e f g");
      expect(scope.remove("a")).toBe(scope);
      expect(scope.toString()).toBe("b c d e f g");
    });

    it("should handle multiple tokens", () => {
      const scope = new BasicScope("a b c d e");
      scope.remove("b c");
      expect(scope.toString()).toBe("a d e");
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a b c d");
      scope.remove(new BasicScope("b c"));
      expect(scope.toString()).toBe("a d");
    });

    it("should handle non-existent tokens gracefully", () => {
      const scope = new BasicScope("a b c");
      scope.remove("d e");
      expect(scope.toString()).toBe("a b c");
    });
  });

  describe("equals", () => {
    it("should return true for equal scopes", () => {
      const scope = new BasicScope("a b c");
      expect(scope.equals("a b c")).toBe(true);
      expect(scope.equals("b c a")).toBe(true);
      expect(scope.equals(new BasicScope("a b c"))).toBe(true);
    });

    it("should return false for different scopes", () => {
      const scope = new BasicScope("a b c");
      expect(scope.equals("a")).toBe(false);
      expect(scope.equals("a b")).toBe(false);
      expect(scope.equals("a b c d")).toBe(false);
      expect(scope.equals("a d c")).toBe(false);
    });
  });

  describe("clear", () => {
    it("should remove all tokens", () => {
      const scope = new BasicScope("a b c");
      expect(scope.clear()).toBe(scope);
      expect(scope.toString()).toBe("");
    });

    it("should allow adding after clear", () => {
      const scope = new BasicScope("a b c");
      scope.clear().add("x y");
      expect(scope.toString()).toBe("x y");
    });
  });

  describe("union", () => {
    it("should combine scopes without modifying originals", () => {
      const scope1 = new BasicScope("a b c e");
      const scope2 = new BasicScope("b d e f");
      const unionScope = BasicScope.union(scope1, scope2);
      expect(unionScope.toString()).toBe("a b c e d f");
      expect(scope1.toString()).toBe("a b c e");
      expect(scope2.toString()).toBe("b d e f");
    });
  });

  describe("intersection", () => {
    it("should find common tokens without modifying originals", () => {
      const scope1 = new BasicScope("a b c e");
      const scope2 = new BasicScope("b d e f");
      const intersectionScope = BasicScope.intersection(scope1, scope2);
      expect(intersectionScope.toString()).toBe("b e");
      expect(scope1.toString()).toBe("a b c e");
      expect(scope2.toString()).toBe("b d e f");
    });

    it("should accept strings as arguments", () => {
      const intersectionScope = BasicScope.intersection("a b c e", "b d e f");
      expect(intersectionScope.toString()).toBe("b e");
    });

    it("should accept mixed BasicScope and string arguments", () => {
      const scope1 = new BasicScope("a b c e");
      const intersectionScope = BasicScope.intersection(scope1, "b d e f");
      expect(intersectionScope.toString()).toBe("b e");
    });
  });

  describe("size", () => {
    it("should return the number of unique tokens", () => {
      expect(new BasicScope().size).toBe(0);
      expect(new BasicScope("a").size).toBe(1);
      expect(new BasicScope("a b c").size).toBe(3);
      expect(new BasicScope("a b a c").size).toBe(3);
    });
  });

  describe("iterator", () => {
    it("should iterate over tokens", () => {
      const scope = new BasicScope("a c b d");
      expect([...scope].sort()).toStrictEqual(["a", "b", "c", "d"]);
    });
  });
});
