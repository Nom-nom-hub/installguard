/**
 * Source-code classification, deliberately separate from command classification.
 *
 * The two look similar and are not. A *command* is one short line the package
 * author chose, so loose matching is cheap there. *Source* is thousands of lines
 * of ordinary JavaScript, and the same loose patterns turn into noise: a
 * function named `downloadedBinPath` is not a network call, and `function (code)`
 * is not the `Function` constructor. Real-world validation across ~350 packages
 * produced exactly those two false positives, which is why this file exists.
 *
 * Rule of thumb applied throughout: match on *what the code does* (a call, a
 * require, a literal URL), never on a word appearing in an identifier.
 */

// ---------------------------------------------------------------------------
// High-signal: code being assembled or decoded at runtime.
// ---------------------------------------------------------------------------
const OBFUSCATED = [
  // `eval(...)` as a call — not the word inside a comment or a property name.
  { re: /(^|[^\w.$])eval\s*\(/, why: "eval() call" },
  // The Function constructor. `function (code) {` must not match, hence [^\w.$]
  // plus the requirement of a capital F followed by `(`.
  { re: /(^|[^\w.$])(new\s+)?Function\s*\(\s*["'`]/, why: "Function() constructor with a string body" },
  { re: /(^|[^\w.$])atob\s*\(/, why: "atob() base64 decode" },
  { re: /Buffer\.from\s*\([^)]*['"]base64['"]/, why: "base64 decode" },
  // Only charcode *literals* are a smuggling signal. `String.fromCharCode(...buffer)`
  // is how esbuild parses a tar header, and flagging it was a false positive.
  { re: /(^|[^\w.$])String\.fromCharCode\s*\(\s*(0x)?\d/, why: "charcode-assembled string" },
  { re: /\bvm\.runIn\w*\s*\(/, why: "vm.runInNewContext" },
  { re: /(?:\\x[0-9a-fA-F]{2}){6,}/, why: "long hex-escaped string" },
];

// ---------------------------------------------------------------------------
// Network access: a real request, or a literal remote URL.
// ---------------------------------------------------------------------------
const NETWORK = [
  { re: /require\s*\(\s*['"](?:node:)?https?['"]\s*\)/, why: "require('https')" },
  { re: /from\s+['"](?:node:)?https?['"]/, why: "import 'https'" },
  // `function fetch(url) {` is a definition, not a request — esbuild has one.
  { re: /(^|[^\w.$])fetch\s*\(/, why: "fetch() call", not: /\b(function|const|let|var)\s+fetch\b/ },
  { re: /require\s*\(\s*['"](?:axios|node-fetch|got|undici|request|superagent|follow-redirects)['"]\s*\)/, why: "http client" },
  { re: /https?:\/\/(?!localhost|127\.0\.0\.1|schemas?\.|www\.w3\.org|json-schema\.org)[\w.-]+/, why: "remote URL literal" },
  { re: /(^|[^\w.$])(XMLHttpRequest|WebSocket)\s*\(/, why: "network client" },
];

// ---------------------------------------------------------------------------
// Process execution. Common and usually legitimate in an install script, so this
// is medium on its own — it only becomes interesting in combination (below).
// ---------------------------------------------------------------------------
const EXEC = [
  { re: /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/, why: "require('child_process')" },
  { re: /from\s+['"](?:node:)?child_process['"]/, why: "import 'child_process'" },
  { re: /(^|[^\w.$])(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/, why: "process spawn" },
];

// Native toolchains: the boring, legitimate reason a package has an install hook.
const NATIVE = [
  { re: /node-gyp|node-pre-gyp|prebuild-install|prebuildify|cmake-js|napi/i, why: "native build toolchain" },
];

// ---------------------------------------------------------------------------
// Secrets. A token *name* in source is worth reporting on its own.
// ---------------------------------------------------------------------------
const SECRETS = [
  { re: /NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET|AWS_ACCESS_KEY|SSH_PRIVATE/, why: "credential environment variable" },
  { re: /\.npmrc|id_rsa|\.aws\/credentials|\.ssh\/|\.docker\/config\.json/, why: "credential file path" },
  // A bare `process.env.SOMETHING` is not a credential read. Escalating on the
  // mere presence of process.env made esbuild (which reads ESBUILD_BINARY_PATH)
  // look like exfiltration — the definition of a scanner nobody trusts.
  { re: /process\.env\s*[.[]\s*['"]?[A-Za-z0-9_]*(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|SESSION)/i, why: "sensitive environment variable", weak: true },
];

function hits(line, patterns) {
  return patterns.filter((p) => p.re.test(line) && !(p.not && p.not.test(line)));
}

const isComment = (t) => t.startsWith("//") || t.startsWith("*") || t.startsWith("/*");

/**
 * Classify one line of source. Returns null when the line says nothing.
 *
 * `weak` findings (a bare `process.env` read) are collected but never reported
 * on their own — they exist so the file-level combination rules below can see
 * them. Reporting every `process.env.NODE_ENV` would drown the real thing.
 */
export function classifySourceLine(line) {
  const all = classifySourceLineAll(line);
  return all.length ? all[0] : null;
}

const PIPE_TO_SHELL = /(curl|wget)[^|"'`]*\|\s*(sudo\s+)?(ba|z)?sh/i;

/**
 * All verdicts for one line, highest risk first.
 *
 * Returning every match rather than the first one matters: a single line like
 * `require('child_process').exec('curl https://x | sh')` is execution *and*
 * network, and it is precisely the co-occurrence that identifies a payload.
 */
export function classifySourceLineAll(line) {
  const t = line.trim();
  if (!t || isComment(t)) return [];
  const out = [];

  if (PIPE_TO_SHELL.test(t)) out.push({ category: "pipe-to-shell", risk: "high", why: "download piped into a shell" });
  for (const h of hits(t, OBFUSCATED)) out.push({ category: "obfuscated-exec", risk: "high", why: h.why });

  const secret = hits(t, SECRETS);
  for (const h of secret.filter((s) => !s.weak)) out.push({ category: "credential-exfil", risk: "high", why: h.why });

  for (const h of hits(t, NETWORK).slice(0, 1)) out.push({ category: "network-download", risk: "medium", why: h.why });
  if (hits(t, NATIVE).length) out.push({ category: "native-build", risk: "low", why: "native build toolchain" });
  for (const h of hits(t, EXEC).slice(0, 1)) out.push({ category: "shell-exec", risk: "medium", why: h.why });
  if (secret.some((s) => s.weak)) out.push({ category: "env-read", risk: "low", why: "environment read", weak: true });

  const order = { high: 0, medium: 1, low: 2 };
  return out.sort((a, b) => order[a.risk] - order[b.risk]);
}

const REPORTABLE = new Set(["high", "medium"]);

/**
 * Classify a whole install-script file.
 *
 * The judgement that matters is not per line but per file: `child_process` is
 * mundane, a remote URL is mundane, and *both plus a token read* is the shape of
 * every recent npm compromise. Combinations are what get escalated to high.
 */
export function classifySourceFile(source) {
  const lines = source.split("\n");
  const found = [];
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    for (const verdict of classifySourceLineAll(lines[i])) {
      found.push({ line: i + 1, ...verdict, text: lines[i].trim().slice(0, 160) });
    }
  }

  const at = (category) => found.find((f) => f.category === category);
  const has = (category) => !!at(category);
  const combos = [];

  // Combination findings carry the line of the evidence that triggered them, so
  // a reviewer (or a SARIF annotation) always has somewhere concrete to look.
  if (has("network-download") && (has("credential-exfil") || has("env-read"))) {
    combos.push({
      line: (at("credential-exfil") ?? at("env-read")).line,
      category: "credential-exfil",
      risk: "high",
      why: "reads credentials/environment and contacts the network",
      text: (at("credential-exfil") ?? at("env-read")).text,
    });
  }
  if (has("network-download") && has("shell-exec") && !has("native-build")) {
    combos.push({
      line: at("shell-exec").line,
      category: "download-exec",
      risk: "high",
      why: "downloads and executes in the same script",
      text: at("shell-exec").text,
    });
  }

  // A packed one-liner in an install script has no innocent explanation.
  const longest = lines.reduce((max, l) => Math.max(max, l.length), 0);
  if (longest > 2000 && lines.length < 25) {
    const line = lines.findIndex((l) => l.length === longest) + 1;
    combos.push({ line, category: "obfuscated-exec", risk: "high", why: `single ${longest}-char line (packed/minified source)`, text: `packed source, ${longest} chars on one line` });
  }

  const evidence = found.filter((f) => REPORTABLE.has(f.risk) && !f.weak);
  // Deduplicate by category so one repeated pattern cannot fill the report.
  const summary = [];
  for (const e of evidence) {
    if (seen.has(e.category) && summary.length >= 5) continue;
    seen.add(e.category);
    summary.push(e);
  }

  const all = [...combos, ...summary];
  const risk = all.some((e) => e.risk === "high") ? "high" : evidence.length ? "medium" : "low";

  return {
    risk,
    combos,
    evidence: summary.slice(0, 5),
    evidenceCount: evidence.length,
    categories: [...new Set(all.map((e) => e.category))],
  };
}
