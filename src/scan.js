import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

const HOOKS = ["preinstall", "install", "postinstall"];

const NATIVE_RE = /node-gyp|node-pre-gyp|prebuild-install|prebuildify|cmake-js|neon |cargo |napi build/i;
const DOWNLOAD_RE = /curl|wget|https?:\/\/|download|fetch .*http/i;
const NAG_RE = /opencollective|funding|thanks|postinstall-?(ad|nag)|donate/i;
const SHELL_RE = /(^|[;&|`])\s*(sh|bash|eval|chmod|sudo)\b|\$\(/i;

// Patterns seen in real supply-chain payloads (chalk/debug, Shai-Hulud): code smuggled
// through an eval/base64 hop, or the environment read and shipped somewhere.
const OBFUSCATED_RE = /\b(eval|atob|Function\s*\(|Buffer\.from\s*\([^)]*base64|child_process|vm\.runIn)/i;
const EXFIL_RE = /process\.env|~\/\.(npmrc|aws|ssh)|\.npmrc|id_rsa|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET/i;
const PIPE_TO_SHELL_RE = /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh/i;
const NODE_EVAL_RE = /\bnode\s+(-e|--eval|-p\b)/i;

/**
 * Classify a single install-script command into a category + risk level.
 *
 * Order matters: the loudest signals are checked first, so a payload that also
 * says "thanks for installing" cannot hide behind the funding-nag category.
 */
export function classifyScript(cmd) {
  const c = String(cmd ?? "");
  if (PIPE_TO_SHELL_RE.test(c)) return { category: "pipe-to-shell", risk: "high" };
  if (EXFIL_RE.test(c) && (DOWNLOAD_RE.test(c) || OBFUSCATED_RE.test(c)))
    return { category: "credential-exfil", risk: "high" };
  if (OBFUSCATED_RE.test(c) || NODE_EVAL_RE.test(c)) return { category: "obfuscated-exec", risk: "high" };
  if (NATIVE_RE.test(c)) return { category: "native-build", risk: "medium" };
  if (DOWNLOAD_RE.test(c)) return { category: "network-download", risk: "high" };
  if (SHELL_RE.test(c)) return { category: "shell-exec", risk: "high" };
  if (NAG_RE.test(c)) return { category: "funding-nag", risk: "low" };
  if (/^node\b|^\.\/|\.js\b|\.cjs\b|\.mjs\b/.test(c.trim())) return { category: "script-exec", risk: "medium" };
  return { category: "other", risk: "medium" };
}

export const RISK_ORDER = { low: 0, medium: 1, high: 2 };

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return null;
  }
}

/** Yield every installed package directory under a node_modules tree (incl. scopes + nested). */
async function* walkModules(nodeModules, depth = 0) {
  if (depth > 8) return;
  let entries;
  try {
    entries = await readdir(nodeModules, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue;
    const full = path.join(nodeModules, entry.name);
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    if (entry.name.startsWith("@")) {
      yield* walkModules(full, depth + 1);
      continue;
    }
    try {
      await stat(path.join(full, "package.json"));
      yield full;
    } catch {
      /* not a package dir */
    }
    yield* walkModules(path.join(full, "node_modules"), depth + 1);
  }
}

/**
 * Scan an installed dependency tree for packages that run code at install time.
 * Returns findings sorted by risk (high first), deduplicated by name@version.
 */
export async function scanTree(projectDir) {
  const findings = new Map();
  for await (const pkgDir of walkModules(path.join(projectDir, "node_modules"))) {
    const pkg = await readJson(path.join(pkgDir, "package.json"));
    if (!pkg?.name || !pkg.scripts) continue;
    const hooks = HOOKS.filter((h) => typeof pkg.scripts[h] === "string" && pkg.scripts[h].trim());
    if (!hooks.length) continue;
    const scripts = hooks.map((hook) => {
      const command = pkg.scripts[hook];
      return { hook, command, ...classifyScript(command) };
    });
    const risk = scripts.reduce((acc, s) => (RISK_ORDER[s.risk] > RISK_ORDER[acc] ? s.risk : acc), "low");
    const key = `${pkg.name}@${pkg.version ?? "0.0.0"}`;
    if (!findings.has(key)) {
      findings.set(key, { name: pkg.name, version: pkg.version ?? null, risk, scripts, path: path.relative(projectDir, pkgDir) });
    }
  }
  return [...findings.values()].sort(
    (a, b) => RISK_ORDER[b.risk] - RISK_ORDER[a.risk] || a.name.localeCompare(b.name),
  );
}

export async function hasNodeModules(projectDir) {
  try {
    await stat(path.join(projectDir, "node_modules"));
    return true;
  } catch {
    return false;
  }
}
