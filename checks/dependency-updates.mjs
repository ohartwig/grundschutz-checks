// Dependencies are watched and updates do not wait: the latest pipeline on
// the default branch ran a dependency or image scan job and passed it, and no
// merge request of the update bot has been open longer than allowed.
//
// Evidences part of DET.5.3 (vulnerability scans with evaluation and
// treatment) and part of DET.5.10 (timely patch management): for the code and
// images of the projects, not for the systems they run on.

import { enc, projects } from "../lib/gitlab.mjs";
import { describe } from "./branch-protection.mjs";

const DAY = 864e5;

export default {
  name: "dependency-updates",
  title: "Dependency scans and timely updates",
  description:
    "For every project, the latest pipeline on the default branch ran and passed a scan job (by name, e.g. dependency, trivy, grype, osv, audit), and no merge request of the update bot is open longer than the days allowed (default 14).",
  method: "TEST",
  requirements: ["DET.5.3", "DET.5.10"],
  partial: ["DET.5.3", "DET.5.10"],
  subjects: (config) => `Every non-archived project of ${describe(config.gitlab)}.`,
  needs: ["gitlab"],
  async run({ config, gitlab, now, note }) {
    const c = config["dependency-updates"] ?? {};
    const scan = new RegExp(c["scan-job"] ?? "dependency|trivy|grype|osv|audit|scan", "i");
    const bots = new Set(c.bots ?? ["pinup-bot", "renovate-bot"]);
    const maxDays = c["max-days-open"] ?? 14;
    const out = [];
    const noCi = [];
    for (const path of await projects(gitlab, config.gitlab)) {
      const p = await gitlab.get(`/projects/${enc(path)}`);
      // No CI, no pipeline to scan in: named in the evidence, not judged.
      if (p.builds_access_level === "disabled") {
        noCi.push(path);
        continue;
      }
      const problems = [];
      const [pl] = await gitlab.get(`/projects/${enc(path)}/pipelines?ref=${enc(p.default_branch ?? "main")}&per_page=1`);
      if (!pl) problems.push("no pipeline on the default branch");
      else {
        const jobs = await gitlab.all(`/projects/${enc(path)}/pipelines/${pl.id}/jobs?include_retried=false`);
        const scans = jobs.filter((j) => scan.test(j.name));
        if (!scans.length) problems.push(`pipeline ${pl.id} has no scan job`);
        else if (scans.some((j) => j.status !== "success")) problems.push(`scan ${scans.filter((j) => j.status !== "success").map((j) => `${j.name} ${j.status}`).join(", ")}`);
      }
      const open = await gitlab.all(`/projects/${enc(path)}/merge_requests?state=opened`);
      const stale = open.filter((m) => bots.has(m.author?.username) && (now.getTime() - Date.parse(m.created_at)) / DAY > maxDays);
      if (stale.length) problems.push(`${stale.length} update(s) open more than ${maxDays} days: !${stale.map((m) => m.iid).join(", !")}`);
      out.push({
        title: path,
        href: p.web_url,
        satisfied: !problems.length,
        detail: problems.length ? problems.join("; ") : "scan passed on the default branch, no update waiting too long",
      });
    }
    if (noCi.length) note(`CI disabled, left out: ${noCi.join(", ")}`);
    return out;
  },
};
