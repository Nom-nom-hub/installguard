import { readFile } from "node:fs/promises";
import path from "node:path";
import { parseNpmLock } from "./lockfiles.js";
import { createRegistry, mapLimit } from "./registry.js";

export { readAnyLock } from "./lockfiles.js";

/** Read name@version pairs from npm's package-lock.json. */
export async function readLockVersions(projectDir) {
  return parseNpmLock(await readFile(path.join(projectDir, "package-lock.json"), "utf8"));
}

/**
 * Fetch the publish timestamp of a specific version.
 *
 * Must use the FULL packument: the abbreviated document served under the
 * `install-v1` accept header omits the `time` map entirely.
 */
export async function fetchPublishTime(name, version, registryOrFetch = fetch) {
  const registry =
    typeof registryOrFetch === "function" ? createRegistry({ fetchImpl: registryOrFetch }) : registryOrFetch;
  const doc = await registry.packumentFull(name);
  const iso = doc?.time?.[version];
  return iso ? new Date(iso) : null;
}

/**
 * Flag dependency versions published less than `days` ago — the window in which
 * a compromised release is most likely to still be live (Shai-Hulud-style worms).
 */
export async function checkCooldown(
  deps,
  { days = 7, now = new Date(), concurrency = 8, fetchImpl = fetch, registry = createRegistry({ fetchImpl }) } = {},
) {
  const cutoff = now.getTime() - days * 86400000;
  const flagged = [];
  let resolved = 0;

  await mapLimit(deps, concurrency, async (dep) => {
    let published = null;
    try {
      published = await fetchPublishTime(dep.name, dep.version, registry);
    } catch {
      return;
    }
    if (!published) return;
    resolved++;
    if (published.getTime() > cutoff) {
      flagged.push({
        ...dep,
        published: published.toISOString(),
        ageHours: Math.round((now.getTime() - published.getTime()) / 3600000),
      });
    }
  });

  flagged.sort((a, b) => a.ageHours - b.ageHours);
  // `resolved` lets the CLI say "checked 57 of 59" instead of implying full coverage
  // when the registry was unreachable or a version was unpublished.
  return Object.assign(flagged, { resolved });
}
