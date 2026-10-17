import { LeaselessLockStore } from "./_test_leaseless_lock_store.ts";
import { runSessionStoreContractTests } from "./testing.ts";

runSessionStoreContractTests({
  describeName: "a store whose expiring refresh lock passes no lease",
  makeStore: () => new LeaselessLockStore(),
});
