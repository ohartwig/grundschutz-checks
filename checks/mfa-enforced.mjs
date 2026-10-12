// Every group named enforces two-factor authentication for its members, with
// a grace period no longer than allowed.
//
// Evidences part of BER.5.9 (multi-factor authentication for far-reaching
// permissions): the group enforces it for everyone in it; whether the second
// factor resists phishing, and who holds rights outside the group, is not seen.

import { enc } from "../lib/gitlab.mjs";

export default {
  name: "mfa-enforced",
  title: "Two-factor authentication enforced",
  description:
    "Every group named requires two-factor authentication of its members, and the grace period for setting it up is at most the hours allowed (default 48).",
  method: "TEST",
  requirements: ["BER.5.9"],
  partial: ["BER.5.9"],
  subjects: (config) => `The groups ${(config.gitlab?.groups ?? []).join(", ") || "(none named)"}.`,
  needs: ["gitlab"],
  async run({ config, gitlab }) {
    const groups = config.gitlab?.groups ?? [];
    const grace = config["mfa-enforced"]?.["max-grace-hours"] ?? 48;
    const out = [];
    for (const path of groups) {
      const g = await gitlab.get(`/groups/${enc(path)}`);
      const problems = [];
      if (!g.require_two_factor_authentication) problems.push("two-factor authentication is not required");
      else if ((g.two_factor_grace_period ?? 0) > grace) problems.push(`grace period ${g.two_factor_grace_period} h, more than ${grace} h`);
      out.push({
        title: path,
        href: g.web_url,
        satisfied: !problems.length,
        detail: problems.length ? problems.join("; ") : `required, grace period ${g.two_factor_grace_period ?? 0} h`,
      });
    }
    return out;
  },
};
