// The default branch of every project: protected, no force push, pushes by
// maintainers (or no one) only, merges only with a green pipeline.
//
// Evidences part of DEV.2.4 (write access to source code is restricted: here
// on the default branch, not on every branch) and part of TEST.4.1 (changes
// are authorised: the gate is enforced, the criteria behind it are not seen).

import { enc, hasCi, projects } from "../lib/gitlab.mjs";

const MAINTAINER = 40;

export default {
  name: "branch-protection",
  title: "Protected default branches",
  description:
    "For every project, the default branch is protected, force push is off, only maintainers (or no one) may push, and a merge request merges only with a successful pipeline.",
  method: "TEST",
  requirements: ["DEV.2.4", "TEST.4.1"],
  partial: ["DEV.2.4", "TEST.4.1"],
  subjects: (config) => `Every non-archived project of ${describe(config.gitlab)}.`,
  needs: ["gitlab"],
  async run({ config, gitlab }) {
    const out = [];
    for (const path of await projects(gitlab, config.gitlab)) {
      const p = await gitlab.get(`/projects/${enc(path)}`);
      const href = p.web_url;
      if (!p.default_branch) {
        out.push({ title: path, href, satisfied: false, detail: "no default branch (empty repository)" });
        continue;
      }
      const pb = await gitlab.get(`/projects/${enc(path)}/protected_branches/${enc(p.default_branch)}`, { missing: "null" });
      const problems = [];
      if (!pb) problems.push(`${p.default_branch} is not protected`);
      else {
        if (pb.allow_force_push) problems.push("force push allowed");
        const push = (pb.push_access_levels ?? []).filter((a) => a.access_level !== 0 && a.access_level < MAINTAINER && !a.deploy_key_id);
        if (push.length) problems.push(`push allowed for ${push.map((a) => a.access_level_description).join(", ")}`);
      }
      // Without CI nothing tests a change before it merges; switching on the
      // pipeline gate there would block every merge, so the finding is the
      // missing CI, not the setting.
      if (!(await hasCi(gitlab, path, p))) problems.push("no CI: changes merge without any pipeline");
      else if (!p.only_allow_merge_if_pipeline_succeeds) problems.push("merges do not need a successful pipeline");
      out.push({
        title: path,
        href,
        satisfied: !problems.length,
        detail: problems.length ? problems.join("; ") : `${p.default_branch} protected, no force push, merge after a green pipeline`,
      });
    }
    return out;
  },
};

export const describe = (g = {}) =>
  [...(g.groups ?? []).map((x) => `group ${x}`), ...(g.projects ?? []).map((x) => `project ${x}`)].join(", ") || "no project";
