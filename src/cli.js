#!/usr/bin/env node
import process from "node:process";
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { scanTree, hasNodeModules, RISK_ORDER } from "./scan.js";
import { buildAllowList, renderConfig, writeConfig } from "./allow.js";
import { checkCooldown } from "./cooldown.js";
import { readAnyLock } from "./lockfiles.js";
import { readBaseline, writeBaseline, diffBaseline, BASELINE_FILE } from "./baseline.js";

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

Commands
  scan      List every dependency with a pre/install/postinstall hook, classified by risk.
  allow     Generate a minimal install-script allow-list (--write applies it).
  cooldown  Flag locked versions published in the last N days (fresh-release risk window).
  diff      Compare the tree against your accepted baseline — new/changed install scripts only.
  accept    Record the current install scripts as reviewed (writes .installguard.json).

Flags
  --ci      Exit 1 when findings are at or above the threshold (default: high).
  --json    Machine-readable output.

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
    }
  }
  const high = shown.filter((f) => f.risk === "high").length;
  console.log(
    `\n${paint("dim", "summary:")} ${high} high · ${shown.filter((f) => f.risk === "medium").length} medium · ${shown.filter((f) => f.risk === "low").length} low`,
  );
  console.log(paint("dim", "next: installguard allow --write   (block all install scripts except native builds)\n"));
  return shown;
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
    const findings = await scanTree(dir);
    if (command === "scan") {
      const minRisk = typeof flags["min-risk"] === "string" ? flags["min-risk"] : "low";
      if (flags.json) console.log(JSON.stringify({ findings }, null, 2));
      else printScan(findings, minRisk);
      const failAt = typeof flags.ci === "string" ? flags.ci : "high";
      return flags.ci && findings.some((f) => RISK_ORDER[f.risk] >= RISK_ORDER[failAt]) ? 1 : 0;
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
    const findings = await scanTree(dir);
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
    const { added, changed, removed } = diffBaseline(findings, baseline);
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
      console.log(paint("green", `✔ none of ${deps.length} versions in ${lockfile} were published in the last ${days} day(s).`));
    } else {
      console.log(paint("bold", `\n${flagged.length} of ${deps.length} versions in ${lockfile} are younger than ${days} day(s)\n`));
      for (const f of flagged) {
        console.log(`${paint("yellow", `${f.ageHours}h`.padStart(6))}  ${f.name}@${f.version} ${paint("dim", f.published)}`);
      }
      console.log(paint("dim", "\nfresh releases are the window where a hijacked publish is still live — pin or wait out the cooldown.\n"));
    }
    return flags.ci && flagged.length ? 1 : 0;
  }

  console.error(`installguard: unknown command "${command}"\n`);
  console.log(HELP);
  return 2;
}

const invokedPath = process.argv[1] ? realpathSync(process.argv[1]) : "";
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().then((code) => process.exit(code));
}
