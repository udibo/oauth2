import { InvalidScopeError } from "../errors.ts";

/** NQCHAR as defined in RFC 6749. */
export const NQCHAR: RegExp = /[\x21\x23-\x5b\x5d-\x7e]/;

/** Regex for validating a scope string. */
export const SCOPE: RegExp = new RegExp(
  `^(?:(?:${NQCHAR.source}+)(?: ${NQCHAR.source}+)*)?$`,
);

/** Regex for extracting scope tokens. */
export const SCOPE_TOKEN: RegExp = new RegExp(`${NQCHAR.source}+`, "g");

/**
 * Base class for OAuth2 scope implementations.
 *
 * Provides the contract that the authorization server, grants, and adapters
 * rely on. Users who want a custom scope type (e.g. one that enforces a
 * fixed vocabulary, or one that encodes hierarchical scopes) can extend
 * this class; the framework only requires a constructor that accepts an
 * optional scope string and the instance methods declared here.
 *
 * The default implementation is {@link BasicScope}; it stores a set of
 * space-delimited NQCHAR tokens per RFC 6749 Section 3.3.
 */
export abstract class AbstractScope {
  /** Deletes all scope tokens from this scope. */
  abstract clear(): this;

  /** Adds all scope tokens in the passed in scope to this scope. */
  abstract add(scope: AbstractScope | string): this;

  /** Removes all scope tokens in the passed in scope from this scope. */
  abstract remove(scope: AbstractScope | string): this;

  /** Checks that this scope has all scope tokens in the passed in scope. */
  abstract has(scope: AbstractScope | string): boolean;

  /** Checks that this scope is equal to the passed in scope. */
  abstract equals(scope: AbstractScope | string): boolean;

  /** Returns the number of scope tokens. */
  abstract get size(): number;

  /** Converts the scope to a string representation. */
  abstract toString(): string;

  /** Converts the scope to a JSON representation. */
  abstract toJSON(): string;

  /** Returns an iterator over the scope's tokens in insertion order. */
  abstract [Symbol.iterator](): IterableIterator<string>;
}

/**
 * Constructor for a scope type. The framework only needs `new Scope(text)`
 * to parse scope strings from incoming requests; static helpers like
 * `from` / `union` / `intersection` remain specific to {@link BasicScope}
 * and are not part of this contract.
 */
export type ScopeConstructor<S extends AbstractScope = BasicScope> = new (
  scope?: string,
) => S;

/** A basic implementation of OAuth2 scope. */
export class BasicScope extends AbstractScope {
  private stringCache?: string;
  private tokens: Set<string>;

  /**
   * Parses a space-delimited scope string into its tokens.
   *
   * @throws {InvalidScopeError} If `scope` contains characters outside the
   * RFC 6749 NQCHAR set.
   */
  constructor(scope?: string) {
    super();
    if (scope && !SCOPE.test(scope)) {
      throw new InvalidScopeError("invalid scope");
    }
    this.tokens = scope ? new Set(scope.match(SCOPE_TOKEN)) : new Set();
  }

  /** Creates a new scope from a scope. */
  static from(scope: BasicScope | string): BasicScope {
    if (typeof scope === "string") return new BasicScope(scope);
    const result = new BasicScope();
    result.add(scope);
    return result;
  }

  /** Creates a new scope with all scope tokens from both scopes. */
  static union(a: BasicScope | string, b: BasicScope | string): BasicScope {
    return BasicScope.from(a).add(b);
  }

  /** Creates a new scope with all scope tokens that are present in both scopes. */
  static intersection(
    a: BasicScope | string,
    b: BasicScope | string,
  ): BasicScope {
    const result = new BasicScope();
    const scopeA = typeof a === "string" ? new BasicScope(a) : a;
    const scopeB = typeof b === "string" ? new BasicScope(b) : b;
    for (const token of scopeA) {
      if (scopeB.tokens.has(token)) result.tokens.add(token);
    }
    return result;
  }

  /** Deletes all scope tokens from this scope. */
  clear(): this {
    this.tokens = new Set<string>();
    delete this.stringCache;
    return this;
  }

  /** Adds all scope tokens in the passed in scope to this scope. */
  add(scope: AbstractScope | string): this {
    const other = typeof scope === "string" ? new BasicScope(scope) : scope;
    for (const token of other) {
      this.tokens.add(token);
    }
    delete this.stringCache;
    return this;
  }

  /** Removes all scope tokens in the passed in scope from this scope. */
  remove(scope: AbstractScope | string): this {
    const other = typeof scope === "string" ? new BasicScope(scope) : scope;
    for (const token of other) {
      this.tokens.delete(token);
    }
    delete this.stringCache;
    return this;
  }

  /** Checks that this scope has all scope tokens in the passed in scope. */
  has(scope: AbstractScope | string): boolean {
    const other = typeof scope === "string" ? new BasicScope(scope) : scope;
    for (const token of other) {
      if (!this.tokens.has(token)) return false;
    }
    return true;
  }

  /** Checks that this scope is equal to the passed in scope. */
  equals(scope: AbstractScope | string): boolean {
    const other = typeof scope === "string" ? new BasicScope(scope) : scope;
    if (this.tokens.size !== other.size) return false;
    for (const token of other) {
      if (!this.tokens.has(token)) return false;
    }
    return true;
  }

  /** Returns the number of scope tokens. */
  get size(): number {
    return this.tokens.size;
  }

  /** Converts the scope to a string representation. */
  toString(): string {
    if (typeof this.stringCache !== "string") {
      this.stringCache = [...this].join(" ");
    }
    return this.stringCache;
  }

  /** Converts the scope to a JSON representation. */
  toJSON(): string {
    return this.toString();
  }

  /** Iterates the scope's tokens in insertion order. */
  *[Symbol.iterator](): IterableIterator<string> {
    yield* this.tokens.values();
  }
}
