import { readFile } from "node:fs/promises";
import path from "node:path";
import { RISK_ORDER } from "./scan.js";
import { classifySourceFile } from "./source.js";

const MAX_BYTES = 512 * 1024;

/**
 * Extract the local file a hook command hands to node.
 * `node install.js`, `node ./scripts/postinstall.cjs --force`, `node -r x ./a.mjs`.
 */
export function referencedScriptFile(command) {
  const match = String(command ?? "").match(/(?:^|\s)((?:\.\/|\.\.\/)?[\w./@-]+\.(?:js|cjs|mjs))(?=\s|$)/);
  if (!match) return null;
  const file = match[1];
  if (path.isAbsolute(file)) return null;
  return file.replace(/^\.\//, "");
}

/**
 * Classify the *contents* of an install script file.
 *
 * This is the gap that matters: nearly every real hook reads `node install.js`,
 * which the command-line classifier can only ever call "script-exec, medium".
 * The payload lives in the file, so that is where we look. The line-level rules
 * live in source.js, kept deliberately stricter than the command-level ones.
 */
export function classifySource(source) {
  const result = classifySourceFile(source);
  return {
    risk: result.risk,
    evidence: [...result.combos, ...result.evidence].slice(0, 5),
    evidenceCount: result.evidenceCount + result.combos.length,
    categories: result.categories,
  };
}

/**
 * Read and classify the files behind a finding's hooks, upgrading its risk when
 * the file contents are worse than the command string suggested.
 */
export async function inspectFinding(projectDir, finding) {
  const scripts = [];
  let risk = finding.risk;
  for (const script of finding.scripts) {
    const file = referencedScriptFile(script.command);
    if (!file) {
      scripts.push(script);
      continue;
    }
    let source;
    try {
      const target = path.resolve(projectDir, finding.path, file);
      const rel = path.relative(path.resolve(projectDir, finding.path), target);
      // Never follow a hook that points outside its own package directory.
      if (rel.startsWith("..")) {
        scripts.push({ ...script, category: "path-escape", risk: "high", sourceFile: file });
        risk = "high";
        continue;
      }
      source = (await readFile(target, "utf8")).slice(0, MAX_BYTES);
    } catch {
      scripts.push({ ...script, sourceFile: file, sourceRead: false });
      continue;
    }
    const deep = classifySource(source);
    const merged = {
      ...script,
      sourceFile: file,
      sourceRead: true,
      sourceRisk: deep.risk,
      evidence: deep.evidence,
      evidenceCount: deep.evidenceCount,
    };
    // Only genuine high-risk source evidence changes the verdict. A medium
    // signal (a spawn, a URL) is attached for the reader but does not inflate
    // the score — that is how a scanner turns into background noise.
    if (deep.risk === "high" && RISK_ORDER[deep.risk] > RISK_ORDER[script.risk]) {
      merged.risk = deep.risk;
      merged.category = deep.evidence[0]?.category ?? script.category;
    }
    scripts.push(merged);
    if (RISK_ORDER[merged.risk] > RISK_ORDER[risk]) risk = merged.risk;
  }
  return { ...finding, risk, scripts };
}

/** Deep-inspect every finding (bounded by the size cap above; all local file reads). */
export async function inspectFindings(projectDir, findings) {
  return Promise.all(findings.map((f) => inspectFinding(projectDir, f)));
}
