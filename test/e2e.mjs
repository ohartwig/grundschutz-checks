// End to end, in CI: the checks against a real estate, their run files through
// results.mjs of the pinned grundschutz-worksheets commit, the results and the
// plan validated against the NIST schema. A check that needs GitLab runs only
// where GITLAB_TOKEN is set; the TLS check always runs.
//
//   node test/e2e.mjs [config]     # default estate/checks.config.json; writes out/
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { WORKSHEETS } from "../tools/worksheets.mjs";
import { CHECKS } from "../checks/index.mjs";

const config = process.argv[2] ?? "estate/checks.config.json";
const ws = ".worksheets";
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", ...opts });
if (!existsSync(`${ws}/.git`) || sh("git", ["-C", ws, "rev-parse", "HEAD"]).trim() !== WORKSHEETS.commit) {
  rmSync(ws, { recursive: true, force: true });
  sh("git", ["init", "-q", ws]);
  sh("git", ["-C", ws, "fetch", "-q", "--depth", "1", WORKSHEETS.repository, WORKSHEETS.commit]);
  sh("git", ["-C", ws, "checkout", "-q", "FETCH_HEAD"]);
  sh("npm", ["ci", "--silent", "--no-audit", "--no-fund"], { cwd: ws });
}
rmSync("out", { recursive: true, force: true });
mkdirSync("out");
const node = (args, opts) => spawnSync(process.execPath, args, { encoding: "utf8", ...opts });
let failed = 0;
const report = (ok, what, detail = "") => {
  failed += !ok;
  console.log(`${ok ? "ok  " : "FAIL"} ${what}${ok || !detail ? "" : `\n${detail}`}`);
};

// The plan first: the runs import it, with its SHA-256.
const plan = node(["run.mjs", "--plan", "--config", config]);
writeFileSync("out/checks.json", plan.stdout);
const ap = node([`${ws}/assessment-plan.mjs`, "out/checks.json"]);
writeFileSync("out/assessment-plan.json", ap.stdout);
report(plan.status === 0 && ap.status === 0, "assessment plan from --plan", plan.stderr + ap.stderr);
if (failed) process.exit(1);

const token = Boolean(process.env.GITLAB_TOKEN);
const cfg = JSON.parse(readFileSync(config, "utf8"));
for (const c of CHECKS.filter((c) => (cfg.checks ?? CHECKS.map((x) => x.name)).includes(c.name))) {
  if (c.needs.includes("gitlab") && !token) {
    console.log(`skip ${c.name}: no GITLAB_TOKEN`);
    continue;
  }
  const r = node(["run.mjs", c.name, "--config", config]);
  if (r.status !== 0) {
    report(false, `${c.name} runs`, r.stderr);
    continue;
  }
  writeFileSync(`out/${c.name}-run.json`, r.stdout);
  const res = node([`${ws}/results.mjs`, `out/${c.name}-run.json`]);
  writeFileSync(`out/${c.name}-results.json`, res.stdout);
  const run = JSON.parse(r.stdout);
  const notAsRequired = run.subjects.filter((s) => !s.satisfied);
  report(res.status === 0, `${c.name}: ${run.subjects.length} subject(s), ${notAsRequired.length} not as required`, res.stderr);
  for (const s of notAsRequired) console.log(`       ${s.title}: ${s.detail}`);
}
const v = node([`${ws}/validate.mjs`, ...readdir("out").filter((f) => /(results|assessment-plan)\.json$/.test(f)).map((f) => `out/${f}`)]);
report(v.status === 0, "everything validates against the NIST schema", v.stdout + v.stderr);
process.exitCode = failed ? 1 : 0;

function readdir(d) {
  return execFileSync("ls", [d], { encoding: "utf8" }).split("\n").filter(Boolean);
}
