const REGISTRY = () => process.env.INSTALLGUARD_REGISTRY || "https://registry.npmjs.org";

const encode = (name) => name.replace("/", "%2f");

/**
 * Registry access, deduplicated per name.
 *
 * Two documents matter and they are NOT interchangeable:
 *  - abbreviated packument (`install-v1` accept header): small, carries
 *    `hasInstallScript` per version, but has **no `time` map**.
 *  - full packument: ~10x bigger, and the only place publish timestamps live.
 *
 * Getting this wrong is silent: publish-time lookups against the abbreviated
 * document return undefined for every version, so a freshness check reports a
 * clean bill of health while checking nothing at all.
 */
export function createRegistry({ fetchImpl = fetch, registry = REGISTRY() } = {}) {
  const abbreviated = new Map();
  const full = new Map();

  async function getJson(url, headers) {
    const res = await fetchImpl(url, headers ? { headers } : undefined);
    if (!res.ok) return null;
    return res.json();
  }

  return {
    /** Abbreviated packument — use for `hasInstallScript`, never for timestamps. */
    async packumentAbbrev(name) {
      if (!abbreviated.has(name)) {
        abbreviated.set(
          name,
          getJson(`${registry}/${encode(name)}`, { accept: "application/vnd.npm.install-v1+json" }).catch(() => null),
        );
      }
      return abbreviated.get(name);
    },
    /** Full packument — required for `time`. One fetch per package name, cached. */
    async packumentFull(name) {
      if (!full.has(name)) full.set(name, getJson(`${registry}/${encode(name)}`).catch(() => null));
      return full.get(name);
    },
    /** Single version document — cheap way to read the declared `scripts`. */
    async versionDoc(name, version) {
      return getJson(`${registry}/${encode(name)}/${encodeURIComponent(version)}`).catch(() => null);
    },
  };
}

/** Run an async worker over items with bounded concurrency. */
export async function mapLimit(items, limit, worker) {
  const out = [];
  let cursor = 0;
  const runners = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      out[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return out;
}
