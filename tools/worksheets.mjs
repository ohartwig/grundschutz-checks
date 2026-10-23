#!/usr/bin/env node
// The grundschutz-worksheets commit the checks are tested against: CI runs
// results.mjs and assessment-plan.mjs of exactly this commit over what the
// checks write, and validates the result. Its public mirror on GitHub, which
// the runners reach without credentials.
//
// pinup announces a newer commit of main as a merge request; its pipeline is
// the test of the checks against the new scripts.
//
//   node tools/worksheets.mjs     # prints the commit, for CI

import { fileURLToPath } from "node:url";

export const WORKSHEETS = {
  repository: "https://github.com/ohartwig/grundschutz-worksheets",
  // renovate: datasource=git-refs depName=ohartwig/grundschutz-worksheets packageName=https://github.com/ohartwig/grundschutz-worksheets branch=main
  commit: "8c8915d655b8a5645660bdb3a996a4b0ee2e7026",
};

if (process.argv[1] === fileURLToPath(import.meta.url)) console.log(WORKSHEETS.commit);
