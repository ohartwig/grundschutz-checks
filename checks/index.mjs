// Every check, in the order --list shows them.
import branchProtection from "./branch-protection.mjs";
import mfaEnforced from "./mfa-enforced.mjs";
import tlsEndpoints from "./tls-endpoints.mjs";
import sbomPresent from "./sbom-present.mjs";
import dependencyUpdates from "./dependency-updates.mjs";

export const CHECKS = [branchProtection, mfaEnforced, tlsEndpoints, sbomPresent, dependencyUpdates];
