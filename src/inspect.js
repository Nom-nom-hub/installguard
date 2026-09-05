import { readFile } from "node:fs/promises";
import path from "node:path";
import { classifyScript, RISK_ORDER } from "./scan.js";

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
 * The payload lives in the file, so that is where we look.
 */
export function classifySource(source) {
  const evidence = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith("//")) continue;
    const { category, risk } = classifyScript(line);
    if (risk === "high") {
      evidence.push({ line: i + 1, category, risk, text: line.trim().slice(0, 160) });
    }
  }
  // A minified or packed file is itself a signal: install scripts have no reason to be one.
  const longest = lines.reduce((max, l) => Math.max(max, l.length), 0);
  if (longest > 2000 && lines.length < 25) {
    evidence.push({ line: 1, category: "obfuscated-exec", risk: "high", text: `single ${longest}-char line (packed/minified source)` });
  }
  const risk = evidence.length ? "high" : "medium";
  return { risk, evidence: evidence.slice(0, 5), evidenceCount: evidence.length };
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
    if (RISK_ORDER[deep.risk] > RISK_ORDER[script.risk]) {
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
