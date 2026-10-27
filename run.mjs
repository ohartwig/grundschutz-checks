#!/usr/bin/env node
// Run one check and write what it saw as a run file for grundschutz-worksheets'
// results.mjs, which turns it into OSCAL assessment results.
//
//   node run.mjs <check> --config checks.config.json > run.json
//   node run.mjs --plan --config checks.config.json > checks.json
//   node run.mjs --list
//
// --plan writes the input of assessment-plan.mjs for every check the config
// enables: the same names, titles, methods and requirements the runs carry,
// so plan and results join by check name.
//
// The config names what to look at, where the plan is and, optionally, who
// answers for the runs (performed_by) (see
// examples/checks.config.json). Tokens come from the environment, never from
// the config: GITLAB_TOKEN, read-only (read_api) is enough.
//
// A check only reads. A failed request, an unknown setting, nothing to look
// at: an error (exit 1) and no run file -- a check that could not look has
// not found anything to be as required. Usage errors exit 2.
//
// No dependencies. Node 24 (LTS) or later.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gitlab as gitlabApi } from "./lib/gitlab.mjs";
import { probe as tlsProbe } from "./lib/tls.mjs";
import { CHECKS } from "./checks/index.mjs";

const usage = "usage: run.mjs <check> --config <file> | --plan --config <file> | --list";

export const main = async (argv, { env = process.env, fetch = globalThis.fetch, probe = tlsProbe, clock = () => new Date() } = {}) => {
  const args = argv.slice();
  const opt = (k) => (args.includes(k) ? args[args.indexOf(k) + 1] : "");
  if (args.includes("--list")) return { code: 0, out: CHECKS.map((c) => `${c.name.padEnd(20)} ${c.title}`).join("\n") + "\n" };
  const configFile = opt("--config");
  const name = args.find((a, i) => !a.startsWith("--") && args[i - 1] !== "--config");
  if (!configFile || (!name && !args.includes("--plan"))) return { code: 2, err: usage };
  const config = JSON.parse(readFileSync(configFile, "utf8"));
  if (!/^[0-9a-f]{40}$/.test(config.catalog?.commit ?? "") || !config.catalog?.path) return { code: 1, err: "config.catalog needs path and a 40-character commit" };
  if (!config.plan?.href) return { code: 1, err: 'config.plan needs "href": the assessment plan the runs follow' };

  if (args.includes("--plan")) {
    if (!config.ssp?.href) return { code: 1, err: 'config.ssp needs "href": the security plan whose claims the checks verify' };
    for (const k of ["id", "title", "version", "last-modified"]) if (!config[k]) return { code: 1, err: `config needs "${k}" for the plan` };
    const enabled = CHECKS.filter((c) => (config.checks ?? CHECKS.map((x) => x.name)).includes(c.name));
    return {
      code: 0,
      out:
        JSON.stringify(
          {
            id: config.id,
            title: config.title,
            version: config.version,
            "last-modified": config["last-modified"],
            ...(config.ssp && { ssp: config.ssp }),
            catalog: config.catalog,
            checks: enabled.map((c) => ({
              check: c.name,
              title: c.title,
              description: c.description,
              method: c.method,
              requirements: c.requirements,
              subjects: c.subjects(config),
              every: config.every?.[c.name] ?? config.every?.default ?? { period: 1, unit: "days" },
            })),
          },
          null,
          2,
        ) + "\n",
    };
  }

  const check = CHECKS.find((c) => c.name === name);
  if (!check) return { code: 2, err: `unknown check ${name}; --list shows them` };
  const notes = [];
  const ctx = {
    config,
    now: clock(),
    probe,
    note: (text) => notes.push(text),
    ...(check.needs.includes("gitlab") && { gitlab: gitlabApi({ url: config.gitlab?.url, token: env.GITLAB_TOKEN, fetch }) }),
  };
  const start = ctx.now;
  let subjects;
  try {
    subjects = await check.run(ctx);
  } catch (e) {
    return { code: 1, err: `${check.name}: ${e.message}` };
  }
  if (!subjects.length) return { code: 1, err: `${check.name}: nothing to look at -- check the config` };
  const end = clock();
  const ci = Boolean(env.CI_JOB_URL);
  // Who ran the checks or answers for the run (BSI-Standard 300-1, 4.3): the
  // config's name, else the user a CI job runs as. Never an empty string.
  const performedBy = [config.performed_by, env.GITLAB_USER_LOGIN].find((v) => typeof v === "string" && v.trim())?.trim();
  const run = {
    check: check.name,
    title: check.title,
    description: check.description,
    method: check.method,
    start: start.toISOString(),
    end: (end > start ? end : start).toISOString(),
    catalog: config.catalog,
    ...(performedBy && { performed_by: performedBy }),
    requirements: check.requirements,
    ...(check.partial?.length && { partial: check.partial }),
    evidence: [...(ci ? [{ text: "the job that measured", href: env.CI_JOB_URL }] : []), ...notes.map((text) => ({ text }))],
    plan: config.plan,
    measured_by: {
      repository: env.CI_PROJECT_PATH || "local",
      commit: /^[0-9a-f]{40}$/.test(env.CI_COMMIT_SHA ?? "") ? env.CI_COMMIT_SHA : "local",
      ...(env.CI_JOB_IMAGE && { image: env.CI_JOB_IMAGE }),
      ...(ci && { job: env.CI_JOB_URL }),
    },
    subjects,
  };
  if (!run.evidence.length) delete run.evidence;
  return { code: 0, out: JSON.stringify(run, null, 2) + "\n", err: notes.map((n) => `${check.name}: ${n}`).join("\n") };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const r = await main(process.argv.slice(2));
  if (r.err) console.error(r.err);
  // One write, no process.exit() after it: on a pipe it would cut the output short.
  if (r.out) process.stdout.write(r.out);
  process.exitCode = r.code;
}
