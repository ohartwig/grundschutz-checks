# grundschutz-checks

Checks that measure requirements of the BSI's Grundschutz++ and write what
they saw as a run file for
[grundschutz-worksheets](https://github.com/ohartwig/grundschutz-worksheets),
whose `results.mjs` turns it into OSCAL assessment results. Run nightly, they
give a dated series of results per requirement: whether a control worked over
a period, not only on one day.

Each check reads, never writes. Where it could not look -- a failed request,
nothing configured -- it writes no run file and exits 1: a check that could
not look has not found anything to be as required.

## The checks

| Check | Looks at | Grundschutz++ | In part |
|---|---|---|---|
| `branch-protection` | the default branch of every project: protected, no force push, pushes by maintainers only, merges only with a green pipeline | DEV.2.4, TEST.4.1 | both: the default branch, not every branch; the gate, not the criteria behind it |
| `mfa-enforced` | every group named requires two-factor authentication, grace period at most 48 h | BER.5.9 | whether the factor resists phishing, and rights outside the group, are not seen |
| `tls-endpoints` | every endpoint named negotiates TLS 1.2 or 1.3, refuses 1.0 and 1.1, has a certificate valid for its name for at least 14 more days | KONF.14.1, KONF.14.1.1 | the endpoints named, not every connection |
| `sbom-present` | the latest release of every project has an SBOM asset (CycloneDX, SPDX) | DEV.4.3, ASST.2.3.2 | ASST.2.3.2: that it exists, not that it is complete |
| `dependency-updates` | the latest default-branch pipeline ran and passed a scan job; no update of the bot open longer than 14 days | DET.5.3, DET.5.10 | both: the code and images, not the systems they run on |

"In part" is not modesty but data: those requirements are listed in the run
file's `partial`, their findings carry `coverage=partial`, and the security
plan of grundschutz-worksheets keeps a partial pass partial unless another
check shows the requirement in full.

Which requirement a check evidences is this repository's judgement, like the
own mappings of grundschutz-worksheets, and like them it is **not yet reviewed
by a person**. Check it against the catalog before you rely on it.

## Use

```bash
# what there is
node run.mjs --list

# the assessment plan's input, for the checks the config enables
node run.mjs --plan --config checks.config.json > checks.json
node ../grundschutz-worksheets/assessment-plan.mjs checks.json > assessment-plan.json

# one check, one run, one result
GITLAB_TOKEN=... node run.mjs branch-protection --config checks.config.json > run.json
node ../grundschutz-worksheets/results.mjs run.json > results.json
```

The config names what to look at; tokens come from the environment, never
from the config. `GITLAB_TOKEN` needs `read_api` and nothing more.
`examples/checks.config.json` shows every setting:

- `catalog`: the Grundschutz++ catalog and the BSI library commit the
  requirement IDs are checked against (by results.mjs).
- `plan`, `ssp`: the assessment plan the runs follow (`file` adds its
  SHA-256) and the security plan it verifies.
- `performed_by`: who ran the checks or answers for them, a person or the
  account a schedule runs as (BSI-Standard 300-1, 4.3); written to every run
  file. Without it a CI run uses `GITLAB_USER_LOGIN`, outside CI the field is
  left out.
- `checks`: which checks run; `every`: how often, for the plan.
- `gitlab`: the instance, and the groups and projects to look at.
- `tls`, `mfa-enforced`, `dependency-updates`: the limits of those checks.
- `accept`, per check: deliberate exceptions, project and reason. An accepted
  project is not looked at, and every run names it with its reason in the
  evidence -- an exception stays visible instead of disappearing.
- `sbom-present.sbom-jobs`: names of further jobs that produce an SBOM, such
  as a supply-chain job that attests one to a pushed artefact.

A run in CI names itself: `measured_by` carries the project, the commit and
the job, and the job is the first piece of evidence. Outside CI it says
`local`.

## How it is tested

`npm test` runs every check against a fake GitLab and a fake TLS probe: what
each finds as required and what not, that a failed request writes nothing,
and that a TLS 1.0/1.1 handshake this client cannot even offer counts as
untested, never as refused.

In CI, `test/e2e.mjs` runs the checks against this estate, passes the run
files through `results.mjs` and `assessment-plan.mjs` of the grundschutz-
worksheets commit pinned in `tools/worksheets.mjs`, and validates everything
against the NIST schema; pinup announces a newer commit as a merge request.

## Development

Development happens in a GitLab project; this GitHub repository is its public
mirror, rewritten and pushed on every change to `main` together with the
release tags (`vX.Y.Z`, see [CHANGELOG.md](CHANGELOG.md)). Issues are welcome
here; a pull request cannot be merged on GitHub, but a change in it will be
carried over by hand.

## Licence

MIT, see [LICENSE](LICENSE).
