import {
  runIdentityUserStoreContractTests,
  runListableSessionServiceContractTests,
  runRevocableSessionServiceContractTests,
} from "./mod.ts";
import {
  sessionFixture,
  userFixture,
} from "./_test_identity_contract_fixtures.ts";
const fault = Deno.env.get("IDENTITY_CONTRACT_FAULT");
if (fault?.startsWith("revoke-")) {
  runRevocableSessionServiceContractTests({
    makeFixture: () => sessionFixture(fault),
  });
} else if (fault?.startsWith("list-")) {
  runListableSessionServiceContractTests({
    makeFixture: () => sessionFixture(fault),
  });
} else {
  runIdentityUserStoreContractTests({
    makeFixture: () => userFixture(fault),
    replaceCredential: true,
    emailVerification: true,
    legacyCredentials: true,
  });
}
