// The latest release of every project has an SBOM: a release asset whose
// name or address names CycloneDX, SPDX or SBOM, or -- where the SBOM is a
// build artefact rather than a release asset -- a successful job that wrote a
// CycloneDX report or is an SBOM job by name (sbom:publish, say), in a
// pipeline of the release tag or of the commit the tag points to. A release
// tool that pushes its tag with the job token starts no tag pipeline; the
// SBOM is then built by the pipeline on that commit.
//
// Evidences DEV.4.3 (the components documented in an SBOM before the release)
// for the releases looked at, and part of ASST.2.3.2 (the SBOM documented):
// that it exists, not that it is complete. A project without any release has
// nothing to check and is left out, by name, in the evidence.

import { enc, projects } from "../lib/gitlab.mjs";
import { describe } from "./branch-protection.mjs";

const SBOM = /sbom|cyclonedx|spdx/i;
// A job that makes an SBOM: by name (sbom:publish), by its CycloneDX report,
// or by a name the config adds -- a supply-chain job that attests an SBOM to a
// pushed artefact rather than keeping it as a file (oras-sources, say).

const NAME = "sbom-present";

export default {
  name: "sbom-present",
  title: "SBOM with every release",
  description:
    "The latest release of every project has an SBOM (CycloneDX or SPDX): as a release asset, or as the artefact of a successful job in a pipeline of its tag or of the commit the tag points to. Projects without a release are left out.",
  method: "EXAMINE",
  requirements: ["DEV.4.3", "ASST.2.3.2"],
  partial: ["ASST.2.3.2"],
  subjects: (config) => `The latest release of every non-archived project of ${describe(config.gitlab)}.`,
  needs: ["gitlab"],
  async run({ config, gitlab, note }) {
    const out = [];
    const without = [];
    const jobs = config[NAME]?.["sbom-jobs"] ? new RegExp(config[NAME]["sbom-jobs"], "i") : null;
    for (const path of await projects(gitlab, config.gitlab, config[NAME]?.accept, note)) {
      const [rel] = await gitlab.get(`/projects/${enc(path)}/releases?per_page=1&order_by=released_at&sort=desc`);
      if (!rel) {
        without.push(path);
        continue;
      }
      const links = rel.assets?.links ?? [];
      const asset = links.find((l) => SBOM.test(l.name ?? "") || SBOM.test(l.url ?? ""));
      let job = null;
      let pipeline = null;
      const looked = [];
      if (!asset) {
        const candidates = [
          ...(await gitlab.get(`/projects/${enc(path)}/pipelines?ref=${enc(rel.tag_name)}&per_page=1`)),
          ...(rel.commit?.id ? await gitlab.get(`/projects/${enc(path)}/pipelines?sha=${rel.commit.id}&per_page=5`) : []),
        ];
        for (const pl of candidates) {
          if (looked.includes(pl.id)) continue;
          looked.push(pl.id);
          const ran = await gitlab.all(`/projects/${enc(path)}/pipelines/${pl.id}/jobs?include_retried=false`);
          job = ran.find(
            (j) =>
              j.status === "success" &&
              ((j.artifacts ?? []).some((a) => a.file_type === "cyclonedx" || (SBOM.test(j.name) && a.file_type === "archive")) || jobs?.test(j.name)),
          );
          if (job) {
            pipeline = pl;
            break;
          }
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
            : `no SBOM among ${links.length} release asset(s), ${looked.length ? `nor in pipeline ${looked.join(", ")} of the tag or its commit` : "no pipeline for the tag or its commit"}`,
      });
    }
    if (without.length) note(`no release, left out: ${without.join(", ")}`);
    return out;
  },
};
