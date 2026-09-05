import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Build a minimal allow-list of packages whose install scripts should still run.
 * Default policy: allow native builds (they genuinely need to compile), block everything else.
 */
export function buildAllowList(findings, { allowRisk = ["medium"], allowCategories = ["native-build"] } = {}) {
  const allow = [];
  const blocked = [];
  for (const f of findings) {
    const needed = f.scripts.some((s) => allowCategories.includes(s.category)) && allowRisk.includes(f.risk);
    (needed ? allow : blocked).push(f.name);
  }
  return { allow: [...new Set(allow)].sort(), blocked: [...new Set(blocked)].sort() };
}

/** Render config snippets for npm (v10–v12), pnpm and yarn. */
export function renderConfig({ allow }) {
  return {
    npmrc: "ignore-scripts=true\n",
    packageJson: {
      pnpm: { onlyBuiltDependencies: allow },
      npm: { installScripts: { allow } },
    },
    yarnrc: `enableScripts: false\n${allow.length ? `\n# re-enable per package via dependenciesMeta:\n${allow.map((a) => `#   "${a}": { built: true }`).join("\n")}\n` : ""}`,
  };
}

/** Write `.npmrc` (ignore-scripts) and pnpm.onlyBuiltDependencies into package.json. */
export async function writeConfig(projectDir, { allow }) {
  const npmrcPath = path.join(projectDir, ".npmrc");
  let npmrc = "";
  try {
    npmrc = await readFile(npmrcPath, "utf8");
  } catch {
    /* new file */
  }
  if (!/^ignore-scripts=/m.test(npmrc)) {
    npmrc = `${npmrc}${npmrc && !npmrc.endsWith("\n") ? "\n" : ""}ignore-scripts=true\n`;
    await writeFile(npmrcPath, npmrc);
  }
  const pkgPath = path.join(projectDir, "package.json");
  const pkg = JSON.parse(await readFile(pkgPath, "utf8"));
  pkg.pnpm = { ...(pkg.pnpm ?? {}), onlyBuiltDependencies: allow };
  await writeFile(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  return { npmrcPath, pkgPath };
}
