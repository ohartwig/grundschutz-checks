// The latest release of every project has an SBOM: a release asset whose
// name or address names CycloneDX, SPDX or SBOM, or -- where the SBOM is a
// build artefact rather than a release asset -- a successful job in the
// release tag's pipeline that wrote a CycloneDX report or is an SBOM job by
// name (sbom:publish, say).
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
  description:
    "The latest release of every project has an SBOM (CycloneDX or SPDX): as a release asset, or as the artefact of a successful job in the pipeline of its tag. Projects without a release are left out.",
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
      const asset = links.find((l) => SBOM.test(l.name ?? "") || SBOM.test(l.url ?? ""));
      let job = null;
      let pipeline = null;
      if (!asset) {
        [pipeline] = await gitlab.get(`/projects/${enc(path)}/pipelines?ref=${enc(rel.tag_name)}&per_page=1`);
        if (pipeline) {
          const jobs = await gitlab.all(`/projects/${enc(path)}/pipelines/${pipeline.id}/jobs?include_retried=false`);
          job = jobs.find((j) => j.status === "success" && (j.artifacts ?? []).some((a) => a.file_type === "cyclonedx" || (SBOM.test(j.name) && a.file_type === "archive")));
        }
      }
      out.push({
        title: `${path} ${rel.tag_name}`,
        href: rel._links?.self,
        satisfied: Boolean(asset || job),
        detail: asset
          ? `SBOM: release asset ${asset.name}`
          : job
            ? `SBOM: job ${job.name} of pipeline ${pipeline.id}`
            : `no SBOM among ${links.length} release asset(s), ${pipeline ? `nor in pipeline ${pipeline.id} of the tag` : "no pipeline for the tag"}`,
      });
    }
    if (without.length) note(`no release, left out: ${without.join(", ")}`);
    return out;
  },
};
