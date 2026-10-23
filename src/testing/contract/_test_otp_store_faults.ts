import { runOtpStoreContractTests } from "./otp-store.ts";
import {
  ManyCodeOtpStore,
  OneCodeOtpStore,
  type OtpStoreFault,
} from "./_test_otp_store_fixtures.ts";

const fault = process.env.OTP_STORE_FAULT;
const describeName = "faulty OtpStore";

if (fault === "one-code-store-as-many") {
  runOtpStoreContractTests({
    describeName,
    makeStore: () => new OneCodeOtpStore(),
  });
} else if (fault === "one-code-store-keeps-replaced-id") {
  runOtpStoreContractTests({
    describeName,
    makeStore: () => new OneCodeOtpStore({ keepsReplacedId: true }),
    oneActiveCode: true,
  });
} else if (fault === "many-code-store-as-one") {
  runOtpStoreContractTests({
    describeName,
    makeStore: () => new ManyCodeOtpStore(),
    oneActiveCode: true,
  });
} else {
  runOtpStoreContractTests({
    describeName,
    makeStore: () => new ManyCodeOtpStore(fault as OtpStoreFault),
  });
}
