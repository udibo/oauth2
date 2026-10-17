import type { AuthorizationCode } from "../../models/authorization-code.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { Token } from "../../models/token.ts";
import type { TestClient, TestUser } from "../_test_fixtures.ts";
import {
  MemoryAuthorizationCodeService,
  MemoryClientService,
  MemoryTokenService,
  MemoryUserService,
} from "../services.ts";
import type {
  CodeExchangeBarriers,
  CodeExchangeContractServices,
} from "./code-exchange.ts";

type TestCode = AuthorizationCode<TestClient, TestUser, BasicScope>;
type TestToken = Token<TestClient, TestUser, BasicScope>;

class CodeLocks {
  readonly #tails = new Map<string, Promise<void>>();

  async hold<T>(code: string, critical: () => Promise<T>): Promise<T> {
    const previous = this.#tails.get(code) ?? Promise.resolve();
    const released = Promise.withResolvers<void>();
    const tail = previous.then(() => released.promise);
    this.#tails.set(code, tail);
    await previous;
    try {
      return await critical();
    } finally {
      released.resolve();
      if (this.#tails.get(code) === tail) this.#tails.delete(code);
    }
  }
}

class LockingAuthorizationCodeService extends MemoryAuthorizationCodeService<
  TestClient,
  TestUser,
  BasicScope
> {
  readonly #locks: CodeLocks;

  constructor(
    services: {
      clientService: MemoryClientService<TestClient, TestUser>;
      userService: MemoryUserService<TestUser>;
    },
    locks: CodeLocks,
  ) {
    super(services);
    this.#locks = locks;
  }

  override revoke(authorizationCode: TestCode | string): Promise<boolean> {
    const code =
      typeof authorizationCode === "string"
        ? authorizationCode
        : authorizationCode.code;
    return this.#locks.hold(code, () => this.revokeHeld(code));
  }

  revokeHeld(code: string): Promise<boolean> {
    return super.revoke(code);
  }
}

class LockingCodeExchangeTokenService extends MemoryTokenService<
  TestClient,
  TestUser,
  BasicScope
> {
  readonly #locks: CodeLocks;
  readonly #codes: LockingAuthorizationCodeService;
  readonly #barriers: CodeExchangeBarriers;
  readonly #awaitsBarrier: boolean;
  readonly #locksCodes: boolean;

  constructor(
    services: {
      clientService: MemoryClientService<TestClient, TestUser>;
      userService: MemoryUserService<TestUser>;
    },
    codes: LockingAuthorizationCodeService,
    locks: CodeLocks,
    barriers: CodeExchangeBarriers,
    shape: { awaitsBarrier: boolean; locksCodes: boolean },
  ) {
    super(services);
    this.#codes = codes;
    this.#locks = locks;
    this.#barriers = barriers;
    this.#awaitsBarrier = shape.awaitsBarrier;
    this.#locksCodes = shape.locksCodes;
  }

  override readonly exchangeCode = (
    authorizationCode: TestCode,
    token: TestToken,
  ): Promise<TestToken | undefined> =>
    this.#locked(authorizationCode.code, async () => {
      const pending = { ...token };
      if (this.#locksCodes) {
        if (!(await this.#codes.get(authorizationCode.code))) return undefined;
      } else if (!(await this.#codes.revokeHeld(authorizationCode.code))) {
        return undefined;
      }
      if (this.#awaitsBarrier) {
        await this.#barriers.afterClaim();
      } else {
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(pending.accessToken),
        );
      }
      await this.save(pending);
      if (this.#locksCodes)
        await this.#codes.revokeHeld(authorizationCode.code);
      return token;
    });

  override revokeCode(code: string, client?: TestClient): Promise<boolean> {
    return this.#locked(code, () => super.revokeCode(code, client));
  }

  #locked<T>(code: string, critical: () => Promise<T>): Promise<T> {
    return this.#locksCodes ? this.#locks.hold(code, critical) : critical();
  }
}

/**
 * Builds a code store and token service shaped like a database-backed pair:
 * `exchangeCode` awaits between its claim and its insert. By default both
 * become visible only when it commits, and `exchangeCode`, `revokeCode` and
 * the code store's `revoke` serialize on a per-code lock. `shape` drops the
 * lock, so the claim is visible before the insert, or leaves the barrier
 * unwired, to prove `runCodeExchangeContractTests` fails such a store.
 */
export function lockingCodeExchangeServices(
  barriers: CodeExchangeBarriers,
  shape: { awaitsBarrier?: boolean; locksCodes?: boolean } = {},
): CodeExchangeContractServices<TestClient, TestUser> {
  const userService = new MemoryUserService<TestUser>();
  const clientService = new MemoryClientService<TestClient, TestUser>(
    userService,
  );
  const locks = new CodeLocks();
  const authorizationCodeService = new LockingAuthorizationCodeService(
    { clientService, userService },
    locks,
  );
  const tokenService = new LockingCodeExchangeTokenService(
    { clientService, userService },
    authorizationCodeService,
    locks,
    barriers,
    {
      awaitsBarrier: shape.awaitsBarrier ?? true,
      locksCodes: shape.locksCodes ?? true,
    },
  );
  return { userService, clientService, authorizationCodeService, tokenService };
}
