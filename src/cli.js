#!/usr/bin/env node
import process from "node:process";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { scanTree, hasNodeModules, RISK_ORDER } from "./scan.js";
import { buildAllowList, renderConfig, writeConfig } from "./allow.js";
import { checkCooldown } from "./cooldown.js";
import { readAnyLock } from "./lockfiles.js";
import { readBaseline, writeBaseline, diffBaseline, BASELINE_FILE } from "./baseline.js";
import { inspectFindings } from "./inspect.js";
import { preflight } from "./preflight.js";
import { buildGraph, pathsTo, blameDirect } from "./graph.js";
import { readPolicy, applyPolicy, renderPolicy, POLICY_FILE } from "./policy.js";
import { toSarif } from "./sarif.js";
import { writeWorkflow, renderWorkflow, WORKFLOW_PATH } from "./ci.js";

const C = {
  reset: "\u001b[0m",
  dim: "\u001b[2m",
  bold: "\u001b[1m",
  red: "\u001b[31m",
  yellow: "\u001b[33m",
  green: "\u001b[32m",
};
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (c, s) => (color ? `${C[c]}${s}${C.reset}` : s);
const RISK_COLOR = { high: "red", medium: "yellow", low: "dim" };

export function parseArgs(argv) {
  const [command = "scan", ...rest] = argv;
  const flags = {};
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith("--")) {
      const [key, inline] = arg.slice(2).split("=");
      const next = rest[i + 1];
      if (inline !== undefined) flags[key] = inline;
      else if (next && !next.startsWith("--")) flags[key] = rest[++i];
      else flags[key] = true;
    } else positional.push(arg);
  }
  return { command, flags, positional };
}

const HELP = `installguard — see and control what runs code when you npm install

Usage
  installguard scan      [--json] [--ci] [--min-risk low|medium|high] [--dir <path>]
  installguard allow     [--write] [--json] [--dir <path>]
  installguard cooldown  [--days 7] [--json] [--ci] [--dir <path>]
  installguard diff      [--json] [--ci] [--dir <path>]
  installguard accept    [--dir <path>]
  installguard preflight [--json] [--ci] [--dir <path>]
  installguard why       <package> [--json] [--dir <path>]
  installguard ci --init [--node 20] [--force] [--dir <path>]

Commands
  scan      List every dependency with a pre/install/postinstall hook, classified by risk.
  allow     Generate a minimal install-script allow-list (--write applies it).
  cooldown  Flag locked versions published in the last N days (fresh-release risk window).
  diff      Compare the tree against your accepted baseline — new/changed install scripts only.
  accept    Record the current install scripts as reviewed (writes .installguard.json).
  preflight Check a lockfile BEFORE installing — no node_modules required.
  why       Show which of your direct dependencies pulls a package in.
  ci        Generate a ready-to-commit GitHub Actions workflow (--init).
  policy    Print a starter policy file from the current tree.

Flags
  --ci        Exit 1 when findings are at or above the threshold (default: high).
  --json      Machine-readable output.
  --no-deep   Skip reading the files behind 'node install.js' (faster, blinder).
  --sarif     Emit SARIF 2.1.0 (scan, preflight) for GitHub's Security tab.
  --policy    Path to a policy file (default .installguardrc.json).

Policy: record reviewed packages in .installguardrc.json with a reason and an
optional expiry. Expired allowances come back as findings instead of lingering.

Typical use: 'accept' once, then 'diff --ci' in CI so you are alerted on change, not volume.
`;

function printScan(findings, minRisk) {
  const shown = findings.filter((f) => RISK_ORDER[f.risk] >= RISK_ORDER[minRisk]);
  if (!shown.length) {
    console.log(paint("green", "✔ No install scripts at or above the threshold."));
    return shown;
  }
  console.log(paint("bold", `\n${shown.length} package(s) run code at install time\n`));
  for (const f of shown) {
    console.log(`${paint(RISK_COLOR[f.risk], f.risk.toUpperCase().padEnd(6))} ${paint("bold", f.name)}@${f.version ?? "?"}`);
    for (const s of f.scripts) {
      console.log(`       ${paint("dim", `${s.hook} [${s.category}]`)} ${s.command}`);
      for (const e of s.evidence ?? []) {
        console.log(`         ${paint("red", "\u2937")} ${paint("dim", `${s.sourceFile}:${e.line} [${e.category}]`)} ${e.text}`);
      }
      if (s.evidenceCount > (s.evidence?.length ?? 0)) {
        console.log(`         ${paint("dim", `\u2026 ${s.evidenceCount - s.evidence.length} more match(es) in ${s.sourceFile}`)}`);
      }
    }
  }
  const high = shown.filter((f) => f.risk === "high").length;
  console.log(
    `\n${paint("dim", "summary:")} ${high} high · ${shown.filter((f) => f.risk === "medium").length} medium · ${shown.filter((f) => f.risk === "low").length} low`,
  );
  console.log(paint("dim", "next: installguard allow --write   (block all install scripts except native builds)\n"));
  return shown;
}

async function toolVersion() {
  try {
    const { default: pkg } = await import("../package.json", { with: { type: "json" } });
    return pkg.version;
  } catch {
    return "0.0.0";
  }
}

function reportPolicy(applied) {
  if (applied.allowed.length) {
    console.log(paint("dim", `\n${applied.allowed.length} finding(s) allowed by ${POLICY_FILE}.`));
  }
  for (const e of applied.expired) {
    console.log(paint("yellow", `! allowance for ${e.name} expired on ${e.policy.expires} — re-review or extend it.`));
  }
}

export async function main(argv = process.argv.slice(2)) {
  const { command, flags } = parseArgs(argv);
  if (flags.help || command === "help" || command === "--help") {
    console.log(HELP);
    return 0;
  }
  if (flags.version || command === "--version") {
    const { default: pkg } = await import("../package.json", { with: { type: "json" } });
    console.log(pkg.version);
    return 0;
  }
  const dir = typeof flags.dir === "string" ? flags.dir : process.cwd();

  if (command === "scan" || command === "allow") {
    if (!(await hasNodeModules(dir))) {
      console.error("installguard: no node_modules/ found — run your package manager's install first.");
      return 2;
    }
    let findings = await scanTree(dir);
    if (flags.deep !== false && flags["no-deep"] !== true) findings = await inspectFindings(dir, findings);
    if (command === "scan") {
      const minRisk = typeof flags["min-risk"] === "string" ? flags["min-risk"] : "low";
      const policy = await readPolicy(dir, typeof flags.policy === "string" ? flags.policy : undefined);
      const applied = applyPolicy(findings, policy);
      if (flags.sarif) {
        console.log(JSON.stringify(toSarif(applied.remaining, { toolVersion: await toolVersion() }), null, 2));
        return 0;
      }
      if (flags.json) console.log(JSON.stringify({ findings: applied.remaining, allowed: applied.allowed, expired: applied.expired }, null, 2));
      else {
        printScan(applied.remaining, minRisk);
        if (policy.exists) reportPolicy(applied);
      }
      const failAt = typeof flags.ci === "string" ? flags.ci : policy.failOn;
      return flags.ci && applied.remaining.some((f) => RISK_ORDER[f.risk] >= RISK_ORDER[failAt]) ? 1 : 0;
    }
    const list = buildAllowList(findings);
    const config = renderConfig(list);
    if (flags.json) {
      console.log(JSON.stringify({ ...list, config }, null, 2));
    } else {
      console.log(paint("bold", `\nAllow (${list.allow.length}) — genuine native builds:`));
      console.log(list.allow.map((n) => `  ✔ ${n}`).join("\n") || paint("dim", "  (none)"));
      console.log(paint("bold", `\nBlock (${list.blocked.length}) — no build step needed:`));
      console.log(list.blocked.map((n) => `  ✖ ${n}`).join("\n") || paint("dim", "  (none)"));
      console.log(paint("dim", "\nrun with --write to apply (.npmrc ignore-scripts + pnpm.onlyBuiltDependencies)\n"));
    }
    if (flags.write) {
      const { npmrcPath, pkgPath } = await writeConfig(dir, list);
      console.log(paint("green", `✔ wrote ${npmrcPath} and ${pkgPath}`));
    }
    return 0;
  }

  if (command === "diff" || command === "accept") {
    if (!(await hasNodeModules(dir))) {
      console.error("installguard: no node_modules/ found — run your package manager's install first.");
      return 2;
    }
    let findings = await scanTree(dir);
    if (flags.deep !== false && flags["no-deep"] !== true) findings = await inspectFindings(dir, findings);
    if (command === "accept") {
      const target = await writeBaseline(dir, findings);
      console.log(paint("green", `✔ baseline written: ${target} (${findings.length} package(s) accepted)`));
      console.log(paint("dim", "commit it, then run `installguard diff --ci` in CI to be alerted on change only.\n"));
      return 0;
    }
    const baseline = await readBaseline(dir);
    if (!baseline) {
      console.error(`installguard: no ${BASELINE_FILE} found — run \`installguard accept\` first.`);
      return 2;
    }
    const policy = await readPolicy(dir, typeof flags.policy === "string" ? flags.policy : undefined);
    let { added, changed, removed } = diffBaseline(findings, baseline);
    const appliedAdded = applyPolicy(added, policy);
    added = appliedAdded.remaining;
    if (flags.json) {
      console.log(JSON.stringify({ added, changed, removed }, null, 2));
    } else if (!added.length && !changed.length) {
      console.log(paint("green", `✔ no new or modified install scripts (${findings.length} accepted, ${removed.length} gone).`));
    } else {
      console.log(paint("bold", `\n${added.length} new · ${changed.length} changed install script(s)\n`));
      for (const f of added) {
        console.log(`${paint(RISK_COLOR[f.risk], "NEW   ")} ${paint("bold", f.name)}@${f.version ?? "?"}`);
        for (const sc of f.scripts) console.log(`       ${paint("dim", `${sc.hook} [${sc.category}]`)} ${sc.command}`);
      }
      for (const f of changed) {
        console.log(`${paint(RISK_COLOR[f.risk], "CHANGE")} ${paint("bold", f.name)}@${f.version ?? "?"} ${paint("dim", `(${f.reasons.join(", ")}; was ${f.previous.version ?? "?"})`)}`);
        for (const sc of f.scripts) {
          const before = f.previous.scripts?.[sc.hook];
          if (before && before !== sc.command) console.log(`       ${paint("dim", `${sc.hook} was`)} ${before}`);
          console.log(`       ${paint("dim", `${sc.hook} [${sc.category}]`)} ${sc.command}`);
        }
      }
      console.log(paint("dim", "\nreview, then `installguard accept` to re-baseline.\n"));
    }
    return flags.ci && (added.length || changed.length) ? 1 : 0;
  }

  if (command === "cooldown") {
    const days = Number(flags.days ?? 7);
    let deps;
    let lockfile;
    try {
      ({ deps, lockfile } = await readAnyLock(dir));
    } catch {
      console.error("installguard: no lockfile found (package-lock.json, pnpm-lock.yaml or yarn.lock).");
      return 2;
    }
    const flagged = await checkCooldown(deps, { days });
    if (flags.json) {
      console.log(JSON.stringify({ days, lockfile, checked: deps.length, flagged }, null, 2));
    } else if (!flagged.length) {
      console.log(paint("green", `✔ none of ${flagged.resolved} resolved versions in ${lockfile} were published in the last ${days} day(s).` +
          (flagged.resolved < deps.length ? paint("dim", ` (${deps.length - flagged.resolved} not resolvable)`) : "")));
    } else {
      console.log(paint("bold", `\n${flagged.length} of ${deps.length} versions in ${lockfile} are younger than ${days} day(s)\n`));
      for (const f of flagged) {
        console.log(`${paint("yellow", `${f.ageHours}h`.padStart(6))}  ${f.name}@${f.version} ${paint("dim", f.published)}`);
      }
      console.log(paint("dim", "\nfresh releases are the window where a hijacked publish is still live — pin or wait out the cooldown.\n"));
    }
    return flags.ci && flagged.length ? 1 : 0;
  }

  if (command === "preflight") {
    let deps;
    let lockfile;
    try {
      ({ deps, lockfile } = await readAnyLock(dir));
    } catch {
      console.error("installguard: no lockfile found (package-lock.json, pnpm-lock.yaml or yarn.lock).");
      return 2;
    }
    const { checked, unknown, findings: allFindings } = await preflight(deps);
    const policy = await readPolicy(dir, typeof flags.policy === "string" ? flags.policy : undefined);
    const applied = applyPolicy(allFindings, policy);
    const findings = applied.remaining;
    if (flags.sarif) {
      console.log(JSON.stringify(toSarif(findings, { toolVersion: await toolVersion(), lockfile }), null, 2));
      return 0;
    }
    if (flags.json) {
      console.log(JSON.stringify({ lockfile, checked, unknown, findings }, null, 2));
    } else if (!findings.length) {
      console.log(paint("green", `\u2714 nothing in ${lockfile} declares an install script (${checked} versions checked).`));
    } else {
      console.log(paint("bold", `\n${findings.length} of ${checked} locked versions will run code on install\n`));
      for (const f of findings) {
        console.log(`${paint(RISK_COLOR[f.risk], f.risk.toUpperCase().padEnd(6))} ${paint("bold", f.name)}@${f.version}${f.dev ? paint("dim", " (dev)") : ""}`);
        for (const sc of f.scripts) console.log(`       ${paint("dim", `${sc.hook} [${sc.category}]`)} ${sc.command}`);
      }
      if (policy.exists) reportPolicy(applied);
      if (unknown) console.log(paint("dim", `\n${unknown} version(s) could not be resolved against the registry.`));
      console.log(paint("dim", "\nthis ran before any of it executed \u2014 'installguard allow --write' to keep it that way.\n"));
    }
    const failAt = typeof flags.ci === "string" ? flags.ci : policy.failOn;
    return flags.ci && findings.some((f) => RISK_ORDER[f.risk] >= RISK_ORDER[failAt]) ? 1 : 0;
  }

  if (command === "ci") {
    if (!flags.init) {
      console.log(renderWorkflow({ nodeVersion: String(flags.node ?? "20") }));
      console.log(paint("dim", `# re-run with --init to write this to ${WORKFLOW_PATH}`));
      return 0;
    }
    const result = await writeWorkflow(dir, { nodeVersion: String(flags.node ?? "20"), force: !!flags.force });
    if (!result.written) {
      console.error(`installguard: ${WORKFLOW_PATH} already exists — pass --force to overwrite.`);
      return 2;
    }
    console.log(paint("green", `✔ wrote ${result.target}`));
    console.log(paint("dim", "it preflights before install, installs with --ignore-scripts, diffs the baseline and uploads SARIF.\n"));
    return 0;
  }

  if (command === "policy") {
    if (!(await hasNodeModules(dir))) {
      console.error("installguard: no node_modules/ found — run your package manager's install first.");
      return 2;
    }
    const findings = await scanTree(dir);
    console.log(JSON.stringify(renderPolicy(findings), null, 2));
    console.error(`\ninstallguard: pipe this into ${POLICY_FILE} and replace each reason with a real one.`);
    return 0;
  }

  if (command === "why") {
    const target = parseArgs(argv).positional[0];
    if (!target) {
      console.error("installguard: usage \u2014 installguard why <package>");
      return 2;
    }
    let graph;
    try {
      graph = await buildGraph(dir);
    } catch {
      console.error("installguard: 'why' needs package-lock.json (npm lockfile).");
      return 2;
    }
    const paths = pathsTo(graph, target);
    if (flags.json) {
      console.log(JSON.stringify({ package: target, version: graph.versions.get(target) ?? null, direct: blameDirect(paths), paths }, null, 2));
      return paths.length ? 0 : 1;
    }
    if (!paths.length) {
      console.log(paint("dim", `no path from ${graph.root} to ${target} \u2014 not in this lockfile.`));
      return 1;
    }
    console.log(paint("bold", `\n${target}@${graph.versions.get(target) ?? "?"} is here because of:\n`));
    for (const p of paths) console.log(`  ${p.map((n, i) => (i === 1 ? paint("bold", n) : n)).join(paint("dim", " \u203a "))}`);
    console.log(paint("dim", `\ndirect dependenc(ies) to change: ${blameDirect(paths).join(", ")}\n`));
    return 0;
  }

  console.error(`installguard: unknown command "${command}"\n`);
  console.log(HELP);
  return 2;
}

const invokedPath = process.argv[1] ? realpathSync(process.argv[1]) : "";
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().then((code) => process.exit(code));
}
