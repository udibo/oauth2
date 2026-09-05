import { assertEquals, assertStrictEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { InvalidScopeError } from "../errors.ts";
import { BasicScope, NQCHAR, SCOPE, SCOPE_TOKEN } from "./scope.ts";

describe("NQCHAR", () => {
  it("should match valid NQCHAR characters", () => {
    assertStrictEquals(NQCHAR.test("!"), true);
    assertStrictEquals(NQCHAR.test("#"), true);
    assertStrictEquals(NQCHAR.test("A"), true);
    assertStrictEquals(NQCHAR.test("z"), true);
    assertStrictEquals(NQCHAR.test("~"), true);
  });

  it("should not match invalid characters", () => {
    assertStrictEquals(NQCHAR.test('"'), false);
    assertStrictEquals(NQCHAR.test("\\"), false);
    assertStrictEquals(NQCHAR.test(" "), false);
  });
});

describe("SCOPE", () => {
  it("should match empty string", () => {
    assertStrictEquals(SCOPE.test(""), true);
  });

  it("should match single token", () => {
    assertStrictEquals(SCOPE.test("a"), true);
    assertStrictEquals(SCOPE.test("read"), true);
  });

  it("should match multiple space-separated tokens", () => {
    assertStrictEquals(SCOPE.test("a b a c"), true);
    assertStrictEquals(SCOPE.test("read write"), true);
    assertStrictEquals(
      SCOPE.test("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~"),
      true,
    );
  });

  it("should not match leading/trailing spaces", () => {
    assertStrictEquals(SCOPE.test(" "), false);
    assertStrictEquals(SCOPE.test(" a"), false);
    assertStrictEquals(SCOPE.test("a "), false);
  });

  it("should not match multiple spaces between tokens", () => {
    assertStrictEquals(SCOPE.test("a  b"), false);
  });

  it("should not match invalid characters", () => {
    assertStrictEquals(SCOPE.test('"'), false);
    assertStrictEquals(SCOPE.test('a"b'), false);
    assertStrictEquals(SCOPE.test('a b"c a d'), false);
    assertStrictEquals(SCOPE.test("\\"), false);
    assertStrictEquals(SCOPE.test("a\\b"), false);
    assertStrictEquals(SCOPE.test("a b\\c a d"), false);
  });
});

describe("SCOPE_TOKEN", () => {
  it("should return null for empty string", () => {
    assertEquals("".match(SCOPE_TOKEN), null);
  });

  it("should extract single token", () => {
    assertEquals("a".match(SCOPE_TOKEN), ["a"]);
  });

  it("should extract multiple tokens", () => {
    assertEquals("a b a c".match(SCOPE_TOKEN), ["a", "b", "a", "c"]);
  });

  it("should extract complex tokens", () => {
    assertEquals("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~".match(SCOPE_TOKEN), [
      "!#0A[]a~",
      "!#1B[]b~",
      "!#0A[]a~",
      "!#2C[]c~",
    ]);
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
      assertStrictEquals(scope.toString(), "");
    });

    it("should throw InvalidBasicScopeError for invalid scope", () => {
      assertThrows(
        () => new BasicScope(" "),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope(" a"),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope("a "),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope("a  b"),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope('"'),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope('a"b'),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope('a b"ca d'),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope("\\"),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope("a\\b"),
        InvalidScopeError,
        "invalid scope",
      );
      assertThrows(
        () => new BasicScope("a b\\c a d"),
        InvalidScopeError,
        "invalid scope",
      );
    });
  });

  describe("toString", () => {
    it("should return deduplicated space-separated tokens", () => {
      let scope = new BasicScope("a");
      assertStrictEquals(scope.toString(), "a");

      scope = new BasicScope("a b a c");
      assertStrictEquals(scope.toString(), "a b c");

      scope = new BasicScope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
      assertStrictEquals(scope.toString(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
    });

    it("should be idempotent", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.toString(), "a b c");
      assertStrictEquals(scope.toString(), "a b c");
    });
  });

  describe("toJSON", () => {
    it("should return same as toString", () => {
      let scope = new BasicScope("a");
      assertStrictEquals(scope.toJSON(), "a");

      scope = new BasicScope("a b a c");
      assertStrictEquals(scope.toJSON(), "a b c");

      scope = new BasicScope("!#0A[]a~ !#1B[]b~ !#0A[]a~ !#2C[]c~");
      assertStrictEquals(scope.toJSON(), "!#0A[]a~ !#1B[]b~ !#2C[]c~");
    });
  });

  describe("from", () => {
    it("should create from string", () => {
      assertStrictEquals(BasicScope.from("a").toString(), "a");
      assertStrictEquals(BasicScope.from("a b a c").toString(), "a b c");
    });

    it("should create copy from BasicScope", () => {
      const original = new BasicScope("a b c");
      const copy = BasicScope.from(original);
      assertStrictEquals(copy.toString(), "a b c");
      copy.add("d");
      assertStrictEquals(original.toString(), "a b c");
      assertStrictEquals(copy.toString(), "a b c d");
    });
  });

  describe("has", () => {
    it("should return true for contained tokens", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.has("a"), true);
      assertStrictEquals(scope.has("b"), true);
      assertStrictEquals(scope.has("c"), true);
    });

    it("should return false for non-contained tokens", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.has("d"), false);
    });

    it("should check multiple tokens", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.has("a b"), true);
      assertStrictEquals(scope.has("b c"), true);
      assertStrictEquals(scope.has("a b c"), true);
      assertStrictEquals(scope.has("c d"), false);
      assertStrictEquals(scope.has("d a"), false);
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.has(new BasicScope("a")), true);
      assertStrictEquals(scope.has(new BasicScope("a b")), true);
      assertStrictEquals(scope.has(new BasicScope("d")), false);
    });
  });

  describe("add", () => {
    it("should add tokens to scope", () => {
      const scope = new BasicScope();
      assertStrictEquals(scope.add("a"), scope);
      assertStrictEquals(scope.toString(), "a");
      assertStrictEquals(scope.add("b"), scope);
      assertStrictEquals(scope.toString(), "a b");
    });

    it("should handle duplicates", () => {
      const scope = new BasicScope("a b");
      scope.add("b c");
      assertStrictEquals(scope.toString(), "a b c");
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a");
      scope.add(new BasicScope("b c"));
      assertStrictEquals(scope.toString(), "a b c");
    });

    it("should return this for chaining", () => {
      const scope = new BasicScope();
      scope.add("a").add("b").add("c");
      assertStrictEquals(scope.toString(), "a b c");
    });
  });

  describe("remove", () => {
    it("should remove tokens from scope", () => {
      const scope = new BasicScope("a b c d e f g");
      assertStrictEquals(scope.remove("a"), scope);
      assertStrictEquals(scope.toString(), "b c d e f g");
    });

    it("should handle multiple tokens", () => {
      const scope = new BasicScope("a b c d e");
      scope.remove("b c");
      assertStrictEquals(scope.toString(), "a d e");
    });

    it("should accept BasicScope instance", () => {
      const scope = new BasicScope("a b c d");
      scope.remove(new BasicScope("b c"));
      assertStrictEquals(scope.toString(), "a d");
    });

    it("should handle non-existent tokens gracefully", () => {
      const scope = new BasicScope("a b c");
      scope.remove("d e");
      assertStrictEquals(scope.toString(), "a b c");
    });
  });

  describe("equals", () => {
    it("should return true for equal scopes", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.equals("a b c"), true);
      assertStrictEquals(scope.equals("b c a"), true);
      assertStrictEquals(scope.equals(new BasicScope("a b c")), true);
    });

    it("should return false for different scopes", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.equals("a"), false);
      assertStrictEquals(scope.equals("a b"), false);
      assertStrictEquals(scope.equals("a b c d"), false);
      assertStrictEquals(scope.equals("a d c"), false);
    });
  });

  describe("clear", () => {
    it("should remove all tokens", () => {
      const scope = new BasicScope("a b c");
      assertStrictEquals(scope.clear(), scope);
      assertStrictEquals(scope.toString(), "");
    });

    it("should allow adding after clear", () => {
      const scope = new BasicScope("a b c");
      scope.clear().add("x y");
      assertStrictEquals(scope.toString(), "x y");
    });
  });

  describe("union", () => {
    it("should combine scopes without modifying originals", () => {
      const scope1 = new BasicScope("a b c e");
      const scope2 = new BasicScope("b d e f");
      const unionScope = BasicScope.union(scope1, scope2);
      assertStrictEquals(unionScope.toString(), "a b c e d f");
      assertStrictEquals(scope1.toString(), "a b c e");
      assertStrictEquals(scope2.toString(), "b d e f");
    });
  });

  describe("intersection", () => {
    it("should find common tokens without modifying originals", () => {
      const scope1 = new BasicScope("a b c e");
      const scope2 = new BasicScope("b d e f");
      const intersectionScope = BasicScope.intersection(scope1, scope2);
      assertStrictEquals(intersectionScope.toString(), "b e");
      assertStrictEquals(scope1.toString(), "a b c e");
      assertStrictEquals(scope2.toString(), "b d e f");
    });

    it("should accept strings as arguments", () => {
      const intersectionScope = BasicScope.intersection("a b c e", "b d e f");
      assertStrictEquals(intersectionScope.toString(), "b e");
    });

    it("should accept mixed BasicScope and string arguments", () => {
      const scope1 = new BasicScope("a b c e");
      const intersectionScope = BasicScope.intersection(scope1, "b d e f");
      assertStrictEquals(intersectionScope.toString(), "b e");
    });
  });

  describe("size", () => {
    it("should return the number of unique tokens", () => {
      assertStrictEquals(new BasicScope().size, 0);
      assertStrictEquals(new BasicScope("a").size, 1);
      assertStrictEquals(new BasicScope("a b c").size, 3);
      assertStrictEquals(new BasicScope("a b a c").size, 3);
    });
  });

  describe("iterator", () => {
    it("should iterate over tokens", () => {
      const scope = new BasicScope("a c b d");
      assertEquals([...scope].sort(), ["a", "b", "c", "d"]);
    });
  });
});
