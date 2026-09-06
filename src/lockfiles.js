import { readFile } from "node:fs/promises";
import path from "node:path";

/**
 * Minimal, dependency-free lockfile readers.
 *
 * We only need `name@version` pairs, so these parse the narrow slice of each
 * format that carries them rather than pulling in a YAML engine — a tool that
 * audits your dependency tree should not add to it.
 */

function dedupe(entries) {
  const out = new Map();
  for (const e of entries) {
    if (!e?.name || !e?.version) continue;
    out.set(`${e.name}@${e.version}`, e);
  }
  return [...out.values()];
}

/** npm: package-lock.json (lockfileVersion 2/3). */
export function parseNpmLock(text) {
  const lock = JSON.parse(text);
  const entries = [];
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key || !entry?.version) continue;
    const name = entry.name ?? key.split("node_modules/").pop();
    // Git-sourced dependencies are a separate hazard: npm runs their `prepare`
    // script (registry tarballs never get one), and the ref they point at can be
    // rewritten upstream without the version ever changing.
    const resolved = typeof entry.resolved === "string" ? entry.resolved : null;
    const git = !!resolved && /^git\+|^github:|^git:/.test(resolved);
    entries.push({ name, version: entry.version, dev: !!entry.dev, resolved, git });
  }
  // lockfileVersion 1 fallback
  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    if (entry?.version && !entries.length) entries.push({ name, version: entry.version, dev: !!entry.dev });
  }
  return dedupe(entries);
}

/**
 * pnpm: pnpm-lock.yaml. Package keys look like
 *   /lodash@4.17.21:            (v6/v7)
 *   /@scope/pkg@1.2.3(peer@1):  (with peer suffix)
 *   'lodash@4.17.21':           (v9 `packages:` / `snapshots:` form)
 */
export function parsePnpmLock(text) {
  const entries = [];
  const re = /^\s{2}'?\/?((?:@[^/\s'@]+\/)?[^/\s'@]+)@([^\s'():]+)/;
  for (const line of text.split("\n")) {
    const m = line.match(re);
    if (m) entries.push({ name: m[1], version: m[2], dev: false });
  }
  return dedupe(entries);
}

/** yarn: yarn.lock, classic (v1) and berry (v2+) — both expose a `version:` field per entry. */
export function parseYarnLock(text) {
  const entries = [];
  let names = [];
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      // Header: one or more comma-separated descriptors ending in a colon.
      names = line
        .replace(/:\s*$/, "")
        .split(",")
        .map((d) => d.trim().replace(/^"|"$/g, ""))
        .map((d) => {
          const at = d.lastIndexOf("@");
          return at > 0 ? d.slice(0, at) : d;
        })
        .filter((n) => n && n !== "__metadata");
      continue;
    }
    const m = line.match(/^\s+"?version"?:?\s+"?([^"\s]+)"?/);
    if (m && names.length) {
      for (const name of new Set(names)) entries.push({ name, version: m[1], dev: false });
      names = [];
    }
  }
  return dedupe(entries);
}

const LOCKFILES = [
  { file: "package-lock.json", manager: "npm", parse: parseNpmLock },
  { file: "npm-shrinkwrap.json", manager: "npm", parse: parseNpmLock },
  { file: "pnpm-lock.yaml", manager: "pnpm", parse: parsePnpmLock },
  { file: "yarn.lock", manager: "yarn", parse: parseYarnLock },
];

/**
 * Find and parse whichever lockfile the project uses.
 * Throws when none is present, so the CLI can print one clear message.
 */
export async function readAnyLock(projectDir) {
  for (const { file, manager, parse } of LOCKFILES) {
    let text;
    try {
      text = await readFile(path.join(projectDir, file), "utf8");
    } catch {
      continue;
    }
    return { manager, lockfile: file, deps: parse(text) };
  }
  throw new Error("no lockfile found (package-lock.json, pnpm-lock.yaml or yarn.lock)");
}
