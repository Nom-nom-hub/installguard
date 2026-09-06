import { classifyScript, RISK_ORDER } from "./scan.js";
import { createRegistry, mapLimit } from "./registry.js";

/**
 * Answer the question every other command answers too late: what will run code
 * when I install this lockfile?
 *
 * `scan` needs node_modules, which means the scripts have already executed on
 * the machine doing the scanning. Preflight works from the lockfile alone, so it
 * can run in CI, in a review bot, or before you trust a fresh `npm ci`.
 *
 * Two-step, to stay cheap: the abbreviated packument carries `hasInstallScript`
 * per version, so one small fetch per package name narrows thousands of deps to
 * a handful; only those get a second fetch for the actual script bodies.
 */
export async function preflight(
  deps,
  { concurrency = 8, fetchImpl = fetch, registry = createRegistry({ fetchImpl }), onProgress } = {},
) {
  // Git dependencies cannot be asked about — the registry has never seen them.
  // They are reported directly, because `prepare` runs on install for exactly
  // these and for nothing else.
  const gitDeps = deps.filter((d) => d.git);
  const registryDeps = deps.filter((d) => !d.git);
  const names = [...new Set(registryDeps.map((d) => d.name))];
  const flagsByName = new Map();

  await mapLimit(names, concurrency, async (name) => {
    const doc = await registry.packumentAbbrev(name);
    flagsByName.set(name, doc?.versions ?? null);
    onProgress?.();
  });

  const candidates = [];
  let unknown = 0;
  for (const dep of registryDeps) {
    const versions = flagsByName.get(dep.name);
    if (!versions) {
      unknown++;
      continue;
    }
    const meta = versions[dep.version];
    if (!meta) {
      unknown++;
      continue;
    }
    if (meta.hasInstallScript) candidates.push(dep);
  }

  const findings = await mapLimit(candidates, concurrency, async (dep) => {
    const doc = await registry.versionDoc(dep.name, dep.version);
    const declared = doc?.scripts ?? {};
    const scripts = ["preinstall", "install", "postinstall"]
      .filter((hook) => typeof declared[hook] === "string" && declared[hook].trim())
      .map((hook) => ({ hook, command: declared[hook], ...classifyScript(declared[hook]) }));
    const risk = scripts.reduce((acc, s) => (RISK_ORDER[s.risk] > RISK_ORDER[acc] ? s.risk : acc), "low");
    return { name: dep.name, version: dep.version, dev: !!dep.dev, risk, scripts, scriptsKnown: scripts.length > 0 };
  });

  for (const dep of gitDeps) {
    findings.push({
      name: dep.name,
      version: dep.version,
      dev: !!dep.dev,
      risk: "medium",
      git: dep.resolved,
      scripts: [{ hook: "prepare", command: `git dependency (${dep.resolved})`, category: "git-dependency", risk: "medium" }],
      scriptsKnown: false,
    });
  }

  findings.sort((a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || a.name.localeCompare(b.name));
  return { checked: deps.length, unknown, git: gitDeps.length, findings };
}
