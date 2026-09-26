import { MemoryAuthRequestStorage } from "../../client/storage.ts";
import { runAuthRequestStorageContractTests } from "./auth-request-storage.ts";

runAuthRequestStorageContractTests({
  describeName: "a store whose clear() wipes live records, run as scoped",
  makeStore: () => new MemoryAuthRequestStorage(),
  clear: "scoped",
});
