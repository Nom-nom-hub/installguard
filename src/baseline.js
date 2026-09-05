import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export const BASELINE_FILE = ".installguard.json";

/**
 * A baseline records the install scripts you have already reviewed and accepted.
 * Once it exists, CI can fail on *change* instead of on volume — which is the
 * difference between a signal and a wall of noise nobody reads.
 */
export function toBaseline(findings) {
  const packages = {};
  for (const f of findings) {
    packages[f.name] = {
      version: f.version,
      risk: f.risk,
      scripts: Object.fromEntries(f.scripts.map((s) => [s.hook, s.command])),
    };
  }
  return { version: 1, generated: new Date().toISOString(), packages };
}

export async function readBaseline(projectDir, file = BASELINE_FILE) {
  try {
    const parsed = JSON.parse(await readFile(path.join(projectDir, file), "utf8"));
    return parsed?.packages ? parsed : null;
  } catch {
    return null;
  }
}

export async function writeBaseline(projectDir, findings, file = BASELINE_FILE) {
  const target = path.join(projectDir, file);
  await writeFile(target, `${JSON.stringify(toBaseline(findings), null, 2)}\n`, "utf8");
  return target;
}

/**
 * Diff current findings against an accepted baseline.
 *
 * - `added`:   packages that did not run install scripts before
 * - `changed`: the script body or risk level moved (a hijacked release rewriting
 *              its own postinstall shows up here even at the same package name)
 * - `removed`: no longer runs anything at install time
 */
export function diffBaseline(findings, baseline) {
  const previous = baseline?.packages ?? {};
  const added = [];
  const changed = [];
  const seen = new Set();

  for (const f of findings) {
    seen.add(f.name);
    const before = previous[f.name];
    if (!before) {
      added.push(f);
      continue;
    }
    const now = Object.fromEntries(f.scripts.map((s) => [s.hook, s.command]));
    const scriptsChanged = JSON.stringify(now) !== JSON.stringify(before.scripts ?? {});
    const riskChanged = before.risk !== f.risk;
    const versionChanged = before.version !== f.version;
    if (scriptsChanged || riskChanged) {
      changed.push({
        ...f,
        previous: { version: before.version, risk: before.risk, scripts: before.scripts ?? {} },
        reasons: [
          scriptsChanged && "script",
          riskChanged && "risk",
          versionChanged && "version",
        ].filter(Boolean),
      });
    }
  }

  const removed = Object.keys(previous)
    .filter((name) => !seen.has(name))
    .map((name) => ({ name, ...previous[name] }));

  return { added, changed, removed };
}
