import type { TestClient, TestUser } from "../_test_fixtures.ts";
import type { BasicScope } from "../../models/scope.ts";
import type { RefreshToken } from "../../models/token.ts";
import { MemoryClientService, MemoryUserService } from "../services.ts";
import { LockingTokenService } from "./_test_locking_token_service.ts";
import {
  runTokenRotationContractTests,
  type TokenRotationBarriers,
} from "./token-rotation.ts";

type TestRefreshToken = RefreshToken<TestClient, TestUser, BasicScope>;

const SERIAL_FAMILY_ID = /^fam_[0-9]+$/;
let serial = 0;

/**
 * A `fam_<n>` store whose `rotate` claims and inserts without the family lock,
 * so a `revokeFamily` that runs while the rotation is held after its claim
 * leaves the successor live.
 */
class UnlockedRotateTokenService extends LockingTokenService<
  TestClient,
  TestUser
> {
  readonly #barriers: TokenRotationBarriers;

  constructor(barriers: TokenRotationBarriers) {
    super(barriers, { familyIdFormat: SERIAL_FAMILY_ID });
    this.#barriers = barriers;
  }

  override async rotate(
    current: TestRefreshToken,
    next: TestRefreshToken,
  ): Promise<TestRefreshToken | undefined> {
    this.checkFamilyId(current.familyId);
    this.checkFamilyId(next.familyId);
    if (!(await this.revokeRotated(current))) return undefined;
    await this.#barriers.afterClaim();
    return await this.save({ ...next });
  }
}

runTokenRotationContractTests<TestClient, TestUser>({
  describeName:
    "a store with fam_<n> family ids whose rotate takes no family lock",
  makeServices: (barriers) => {
    const userService = new MemoryUserService<TestUser>();
    const clientService = new MemoryClientService<TestClient, TestUser>(
      userService,
    );
    const tokenService = new UnlockedRotateTokenService(barriers);
    return { userService, clientService, tokenService };
  },
  addUser: (svc, user, pw) =>
    (svc as MemoryUserService<TestUser>).add(user, pw),
  addClient: (svc, client) =>
    (svc as MemoryClientService<TestClient, TestUser>).add(client),
  makeFamilyId: () => `fam_${++serial}`,
});
