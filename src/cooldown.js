import { readFile } from "node:fs/promises";
import path from "node:path";
import { parseNpmLock } from "./lockfiles.js";

export { readAnyLock } from "./lockfiles.js";

const REGISTRY = process.env.INSTALLGUARD_REGISTRY || "https://registry.npmjs.org";

/** Read name@version pairs from npm's package-lock.json (v2/v3). */
export async function readLockVersions(projectDir) {
  return parseNpmLock(await readFile(path.join(projectDir, "package-lock.json"), "utf8"));
}

/** Fetch the publish timestamp of a specific version from the registry. */
export async function fetchPublishTime(name, version, fetchImpl = fetch) {
  const res = await fetchImpl(`${REGISTRY}/${name.replace("/", "%2f")}`, {
    headers: { accept: "application/vnd.npm.install-v1+json" },
  });
  if (!res.ok) return null;
  const body = await res.json();
  const iso = body?.time?.[version];
  return iso ? new Date(iso) : null;
}

/**
 * Flag dependency versions published less than `days` ago — the window in which
 * a compromised release is most likely to still be live (Shai-Hulud-style worms).
 */
export async function checkCooldown(deps, { days = 7, now = new Date(), concurrency = 8, fetchImpl = fetch } = {}) {
  const cutoff = now.getTime() - days * 86400000;
  const flagged = [];
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, deps.length) }, async () => {
    while (cursor < deps.length) {
      const dep = deps[cursor++];
      let published = null;
      try {
        published = await fetchPublishTime(dep.name, dep.version, fetchImpl);
      } catch {
        continue;
      }
      if (published && published.getTime() > cutoff) {
        flagged.push({
          ...dep,
          published: published.toISOString(),
          ageHours: Math.round((now.getTime() - published.getTime()) / 3600000),
        });
      }
    }
  });
  await Promise.all(workers);
  return flagged.sort((a, b) => a.ageHours - b.ageHours);
}
