// The checks against a fake GitLab and a fake TLS probe: what each finds as
// required and what not, and how run.mjs turns it into a run file. No network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../run.mjs";

const NOW = new Date("2026-10-12T03:00:00Z");
const GL = "https://gitlab.test";
const p = (path) => encodeURIComponent(path);

// GitLab as a map from request path (without paging) to answer.
const api = {
  [`/groups/${p("acme")}/projects?include_subgroups=true&archived=false&with_shared=false`]: [
    { path_with_namespace: "acme/good" },
    { path_with_namespace: "acme/loose" },
    { path_with_namespace: "acme/open" },
  ],
  [`/groups/${p("acme")}`]: { web_url: `${GL}/acme`, require_two_factor_authentication: true, two_factor_grace_period: 24 },
  [`/groups/${p("lax")}`]: { web_url: `${GL}/lax`, require_two_factor_authentication: true, two_factor_grace_period: 336 },
  [`/groups/${p("none")}`]: { web_url: `${GL}/none`, require_two_factor_authentication: false },
  [`/projects/${p("acme/good")}`]: { web_url: `${GL}/acme/good`, default_branch: "main", only_allow_merge_if_pipeline_succeeds: true },
  [`/projects/${p("acme/loose")}`]: { web_url: `${GL}/acme/loose`, default_branch: "main", only_allow_merge_if_pipeline_succeeds: false },
  [`/projects/${p("acme/open")}`]: { web_url: `${GL}/acme/open`, default_branch: "trunk", only_allow_merge_if_pipeline_succeeds: true },
  [`/projects/${p("acme/good")}/protected_branches/main`]: { allow_force_push: false, push_access_levels: [{ access_level: 40, access_level_description: "Maintainers" }] },
  [`/projects/${p("acme/loose")}/protected_branches/main`]: { allow_force_push: true, push_access_levels: [{ access_level: 30, access_level_description: "Developers + Maintainers" }] },
  [`/projects/${p("acme/good")}/releases?order_by=released_at&sort=desc`]: [
    { tag_name: "v1.2.0", _links: { self: `${GL}/acme/good/-/releases/v1.2.0` }, assets: { links: [{ name: "sbom.cdx.json", url: "https://x/sbom.cdx.json" }] } },
  ],
  [`/projects/${p("acme/loose")}/releases?order_by=released_at&sort=desc`]: [
    { tag_name: "v0.3.0", _links: { self: `${GL}/acme/loose/-/releases/v0.3.0` }, assets: { links: [{ name: "binary.tar.gz", url: "https://x/b" }] } },
  ],
  [`/projects/${p("acme/open")}/releases?order_by=released_at&sort=desc`]: [],
  [`/projects/${p("acme/good")}/pipelines?ref=main`]: [{ id: 11 }],
  [`/projects/${p("acme/loose")}/pipelines?ref=main`]: [{ id: 12 }],
  [`/projects/${p("acme/open")}/pipelines?ref=trunk`]: [],
  [`/projects/${p("acme/good")}/pipelines/11/jobs?include_retried=false`]: [{ name: "test", status: "success" }, { name: "trivy-scan", status: "success" }],
  [`/projects/${p("acme/loose")}/pipelines/12/jobs?include_retried=false`]: [{ name: "test", status: "success" }],
  [`/projects/${p("acme/good")}/merge_requests?state=opened`]: [{ iid: 3, author: { username: "pinup-bot" }, created_at: "2026-10-10T00:00:00Z" }],
  [`/projects/${p("acme/loose")}/merge_requests?state=opened`]: [
    { iid: 7, author: { username: "pinup-bot" }, created_at: "2026-09-01T00:00:00Z" },
    { iid: 8, author: { username: "someone" }, created_at: "2026-01-01T00:00:00Z" },
  ],
  [`/projects/${p("acme/open")}/merge_requests?state=opened`]: [],
  // SBOM as a build artefact of the tag pipeline; one release with none; a project without CI.
  [`/projects/${p("acme/loose")}/pipelines?ref=v0.3.0`]: [{ id: 30 }],
  [`/projects/${p("acme/loose")}/pipelines/30/jobs?include_retried=false`]: [{ name: "sbom:publish", status: "success", artifacts: [{ file_type: "archive" }] }],
  [`/projects/${p("acme/bare")}`]: { web_url: `${GL}/acme/bare`, default_branch: "main", only_allow_merge_if_pipeline_succeeds: true },
  [`/projects/${p("acme/bare")}/releases?order_by=released_at&sort=desc`]: [{ tag_name: "v2.0.0", _links: { self: `${GL}/acme/bare/-/releases/v2.0.0` }, assets: { links: [] } }],
  [`/projects/${p("acme/bare")}/pipelines?ref=v2.0.0`]: [{ id: 40 }],
  [`/projects/${p("acme/bare")}/pipelines/40/jobs?include_retried=false`]: [{ name: "build", status: "success", artifacts: [{ file_type: "archive" }] }, { name: "sbom:publish", status: "failed", artifacts: [] }],
  [`/projects/${p("acme/noci")}`]: { web_url: `${GL}/acme/noci`, default_branch: "main", builds_access_level: "disabled", only_allow_merge_if_pipeline_succeeds: false },
  [`/projects/${p("acme/noci")}/protected_branches/main`]: { allow_force_push: false, push_access_levels: [{ access_level: 40, access_level_description: "Maintainers" }] },
};
const fakeFetch = async (url) => {
  const u = new URL(url);
  u.searchParams.delete("per_page");
  u.searchParams.delete("page");
  const path = u.pathname.replace("/api/v4", "") + (u.search || "");
  const body = api[path];
  if (body === undefined) return new Response("{}", { status: 404 });
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
};
const fakeProbe = async (host) =>
  ({
    "good.test": { protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", authorized: true, validTo: "2027-01-01T00:00:00.000Z", legacy: "refused", legacyError: "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" },
    "old.test": { protocol: "TLSv1.2", cipher: "ECDHE-RSA-AES128-GCM-SHA256", authorized: true, validTo: "2027-01-01T00:00:00.000Z", legacy: "accepted TLSv1.1", legacyError: "" },
    "expiring.test": { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", authorized: true, validTo: "2026-10-20T00:00:00.000Z", legacy: "refused", legacyError: "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION" },
    "blind.test": { protocol: "TLSv1.3", cipher: "TLS_AES_128_GCM_SHA256", authorized: true, validTo: "2027-01-01T00:00:00.000Z", legacy: "untested", legacyError: "ERR_SSL_NO_PROTOCOLS_AVAILABLE" },
    "down.test": { error: "ECONNREFUSED", legacy: "untested", legacyError: "ECONNREFUSED" },
  })[host];

const dir = mkdtempSync(join(tmpdir(), "checks-"));
const base = {
  id: "test-checks",
  ssp: { href: "security-plan.json" },
  title: "Test checks",
  version: "1",
  "last-modified": "2026-10-12T00:00:00Z",
  catalog: { path: "control_layer/Grundschutz++/Grundschutz++-resolved_catalog.json", commit: "a12831136f4122a4c43854622180a24f2576a41e" },
  plan: { href: "assessment-plan.json" },
  gitlab: { url: GL, groups: ["acme"] },
  tls: { endpoints: ["good.test", "old.test", "expiring.test", "blind.test", "down.test:8443"] },
};
const configFile = (change = (c) => c) => {
  const f = join(dir, `config-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(f, JSON.stringify(change(structuredClone(base))));
  return f;
};
const env = { GITLAB_TOKEN: "t", CI_JOB_URL: "https://gitlab.test/ci/-/jobs/5", CI_PROJECT_PATH: "acme/checks", CI_COMMIT_SHA: "c".repeat(40) };
const run = async (name, change, extra = {}) => {
  const r = await main([name, "--config", configFile(change)], { env, fetch: fakeFetch, probe: fakeProbe, clock: () => NOW, ...extra });
  return { ...r, run: r.code === 0 ? JSON.parse(r.out) : null };
};
const by = (r) => Object.fromEntries(r.run.subjects.map((s) => [s.title, s]));

test("branch-protection: protected, no force push, maintainers, green pipeline", async () => {
  const r = await run("branch-protection");
  assert.equal(r.code, 0, r.err);
  const s = by(r);
  assert.equal(s["acme/good"].satisfied, true);
  assert.equal(s["acme/loose"].satisfied, false);
  assert.match(s["acme/loose"].detail, /force push allowed.*Developers \+ Maintainers.*green|successful pipeline/);
  assert.equal(s["acme/open"].satisfied, false);
  assert.match(s["acme/open"].detail, /trunk is not protected/);
  assert.deepEqual(r.run.partial, ["DEV.2.4", "TEST.4.1"]);
});

test("mfa-enforced: required, with a grace period not longer than allowed", async () => {
  const r = await run("mfa-enforced", (c) => ({ ...c, gitlab: { ...c.gitlab, groups: ["acme", "lax", "none"] } }));
  assert.equal(r.code, 0, r.err);
  const s = by(r);
  assert.equal(s.acme.satisfied, true);
  assert.match(s.lax.detail, /grace period 336 h, more than 48 h/);
  assert.match(s.none.detail, /not required/);
});

test("tls-endpoints: current TLS, old TLS refused, certificate valid long enough; untested is not passed", async () => {
  const r = await run("tls-endpoints");
  assert.equal(r.code, 0, r.err);
  const s = by(r);
  assert.equal(s["good.test"].satisfied, true);
  assert.match(s["old.test"].detail, /accepts TLSv1\.1/);
  assert.match(s["expiring.test"].detail, /expires in 7 days/);
  assert.equal(s["blind.test"].satisfied, false);
  assert.match(s["blind.test"].detail, /could not be tested/);
  assert.match(s["down.test:8443"].detail, /no TLS handshake: ECONNREFUSED/);
  assert.equal(s["down.test:8443"].href, "https://down.test:8443/");
});

test("sbom-present: a release asset or an SBOM job of the tag pipeline; a project without release is named, not judged", async () => {
  const r = await run("sbom-present", (c) => ({ ...c, gitlab: { ...c.gitlab, projects: ["acme/bare"] } }));
  assert.equal(r.code, 0, r.err);
  const s = by(r);
  assert.match(s["acme/good v1.2.0"].detail, /^SBOM: release asset sbom\.cdx\.json$/);
  assert.match(s["acme/loose v0.3.0"].detail, /^SBOM: job sbom:publish of pipeline 30$/);
  assert.equal(s["acme/bare v2.0.0"].satisfied, false);
  assert.match(s["acme/bare v2.0.0"].detail, /no SBOM among 0 release asset\(s\), nor in pipeline 40/);
  assert.equal(Object.keys(s).length, 3);
  assert.deepEqual(r.run.evidence.at(-1), { text: "no release, left out: acme/open" });
  assert.deepEqual(r.run.partial, ["ASST.2.3.2"]);
});

test("without CI: no pipeline gate to ask for, nothing to scan", async () => {
  const bp = await run("branch-protection", (c) => ({ ...c, gitlab: { url: GL, projects: ["acme/noci"] } }));
  assert.equal(bp.code, 0, bp.err);
  assert.equal(bp.run.subjects[0].satisfied, true);
  assert.match(bp.run.subjects[0].detail, /no CI/);
  const du = await run("dependency-updates", (c) => ({ ...c, gitlab: { url: GL, projects: ["acme/noci", "acme/good"] } }));
  assert.equal(du.code, 0, du.err);
  assert.deepEqual(du.run.subjects.map((s) => s.title), ["acme/good"]);
  assert.deepEqual(du.run.evidence.at(-1), { text: "CI disabled, left out: acme/noci" });
});

test("dependency-updates: a passed scan job, no update of the bot waiting too long", async () => {
  const r = await run("dependency-updates");
  assert.equal(r.code, 0, r.err);
  const s = by(r);
  assert.equal(s["acme/good"].satisfied, true);
  assert.match(s["acme/loose"].detail, /has no scan job; 1 update\(s\) open more than 14 days: !7$/);
  assert.match(s["acme/open"].detail, /no pipeline on the default branch/);
});

test("the run file carries what results.mjs needs: plan, catalog, who measured, when", async () => {
  const r = await run("branch-protection");
  assert.equal(r.run.check, "branch-protection");
  assert.equal(r.run.start, NOW.toISOString());
  assert.deepEqual(r.run.plan, { href: "assessment-plan.json" });
  assert.equal(r.run.catalog.commit, base.catalog.commit);
  assert.deepEqual(r.run.measured_by, { repository: "acme/checks", commit: "c".repeat(40), job: env.CI_JOB_URL });
  assert.deepEqual(r.run.evidence[0], { text: "the job that measured", href: env.CI_JOB_URL });
  const local = await main(["branch-protection", "--config", configFile()], { env: { GITLAB_TOKEN: "t" }, fetch: fakeFetch, probe: fakeProbe, clock: () => NOW });
  assert.deepEqual(JSON.parse(local.out).measured_by, { repository: "local", commit: "local" });
});

test("a check that could not look writes nothing", async () => {
  const failing = async () => new Response("{}", { status: 500 });
  const r = await run("branch-protection", undefined, { fetch: failing });
  assert.equal(r.code, 1);
  assert.equal(r.out, undefined);
  assert.match(r.err, /500/);
  const empty = await run("mfa-enforced", (c) => ({ ...c, gitlab: { ...c.gitlab, groups: [] } }));
  assert.equal(empty.code, 1);
  assert.match(empty.err, /nothing to look at/);
});

test("usage and config errors", async () => {
  assert.equal((await run("no-such-check")).code, 2);
  assert.equal((await main(["branch-protection"], {})).code, 2);
  const noPlan = await run("tls-endpoints", (c) => ({ ...c, plan: undefined }));
  assert.equal(noPlan.code, 1);
  assert.match(noPlan.err, /config\.plan/);
});

test("--plan writes the input of assessment-plan.mjs for the enabled checks", async () => {
  const r = await main(["--plan", "--config", configFile((c) => ({ ...c, checks: ["tls-endpoints", "mfa-enforced"] }))], {});
  assert.equal(r.code, 0, r.err);
  const plan = JSON.parse(r.out);
  assert.deepEqual(plan.checks.map((c) => c.check), ["mfa-enforced", "tls-endpoints"]);
  assert.deepEqual(plan.checks[1].requirements, ["KONF.14.1", "KONF.14.1.1"]);
  assert.match(plan.checks[1].subjects, /good\.test/);
  assert.deepEqual(plan.checks[0].every, { period: 1, unit: "days" });
  const noSsp = await main(["--plan", "--config", configFile((c) => ({ ...c, ssp: undefined }))], {});
  assert.equal(noSsp.code, 1);
  assert.match(noSsp.err, /config\.ssp/);
});
