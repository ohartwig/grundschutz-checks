// The latest release of every project carries an SBOM: a release asset
// whose name or address names CycloneDX, SPDX or SBOM.
//
// Evidences DEV.4.3 (the components documented in an SBOM before the release)
// for the releases looked at, and part of ASST.2.3.2 (the SBOM documented):
// that it exists, not that it is complete. A project without any release has
// nothing to check and is left out, by name, in the evidence.

import { enc, projects } from "../lib/gitlab.mjs";
import { describe } from "./branch-protection.mjs";

const SBOM = /sbom|cyclonedx|spdx/i;

export default {
  name: "sbom-present",
  title: "SBOM with every release",
  description: "The latest release of every project has a release asset that is an SBOM (CycloneDX or SPDX). Projects without a release are left out.",
  method: "EXAMINE",
  requirements: ["DEV.4.3", "ASST.2.3.2"],
  partial: ["ASST.2.3.2"],
  subjects: (config) => `The latest release of every non-archived project of ${describe(config.gitlab)}.`,
  needs: ["gitlab"],
  async run({ config, gitlab, note }) {
    const out = [];
    const without = [];
    for (const path of await projects(gitlab, config.gitlab)) {
      const [rel] = await gitlab.get(`/projects/${enc(path)}/releases?per_page=1&order_by=released_at&sort=desc`);
      if (!rel) {
        without.push(path);
        continue;
      }
      const links = rel.assets?.links ?? [];
      const sbom = links.find((l) => SBOM.test(l.name ?? "") || SBOM.test(l.url ?? ""));
      out.push({
        title: `${path} ${rel.tag_name}`,
        href: rel._links?.self,
        satisfied: Boolean(sbom),
        detail: sbom ? `SBOM: ${sbom.name}` : `no SBOM among ${links.length} asset(s)`,
      });
    }
    if (without.length) note(`no release, left out: ${without.join(", ")}`);
    return out;
  },
};
