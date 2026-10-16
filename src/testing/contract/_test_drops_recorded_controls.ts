import type { AuthRequestRecord } from "../../client/storage.ts";
import { MemoryAuthRequestStorage } from "../../client/storage.ts";
import { runAuthRequestStorageContractTests } from "./auth-request-storage.ts";

class KnownColumnsAuthRequestStorage extends MemoryAuthRequestStorage {
  override set(
    state: string,
    { codeVerifier, returnTo, scope, createdAt }: AuthRequestRecord,
  ): void {
    super.set(state, { codeVerifier, returnTo, scope, createdAt });
  }
}

runAuthRequestStorageContractTests({
  describeName: "a store that keeps only the fields it knows",
  makeStore: () => new KnownColumnsAuthRequestStorage(),
});
