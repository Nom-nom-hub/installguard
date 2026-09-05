import { readFile } from "node:fs/promises";
import path from "node:path";

export const POLICY_FILE = ".installguardrc.json";

/**
 * A policy records decisions your team already made, with the two things a
 * bare allow-list always loses: *why*, and *for how long*.
 *
 * ```json
 * {
 *   "allow": {
 *     "esbuild": { "reason": "fetches its own platform binary; reviewed by @sam", "expires": "2026-12-01" },
 *     "sharp": { "reason": "native build" }
 *   },
 *   "failOn": "high"
 * }
 * ```
 *
 * An expired entry is never silently honoured — it comes back as a finding, so
 * "we looked at it once in 2024" cannot quietly become policy forever.
 */
export async function readPolicy(projectDir, file = POLICY_FILE) {
  try {
    const parsed = JSON.parse(await readFile(path.join(projectDir, file), "utf8"));
    return normalizePolicy(parsed);
  } catch {
    return normalizePolicy(null);
  }
}

export function normalizePolicy(raw) {
  const allow = {};
  for (const [name, value] of Object.entries(raw?.allow ?? {})) {
    if (value === true) allow[name] = { reason: null, expires: null };
    else if (typeof value === "string") allow[name] = { reason: value, expires: null };
    else if (value && typeof value === "object") allow[name] = { reason: value.reason ?? null, expires: value.expires ?? null };
  }
  return { allow, failOn: raw?.failOn ?? "high", exists: !!raw };
}

/**
 * Split findings into what the policy covers and what it does not.
 *
 * `expired` is deliberately kept out of `allowed`: an allowance past its date is
 * an unreviewed finding again, and it says so out loud.
 */
export function applyPolicy(findings, policy, now = new Date()) {
  const remaining = [];
  const allowed = [];
  const expired = [];
  for (const finding of findings) {
    const rule = policy.allow[finding.name];
    if (!rule) {
      remaining.push(finding);
      continue;
    }
    if (rule.expires) {
      const until = new Date(rule.expires);
      if (Number.isNaN(until.getTime())) {
        remaining.push({ ...finding, policyError: `invalid expires "${rule.expires}"` });
        continue;
      }
      if (until.getTime() < now.getTime()) {
        expired.push({ ...finding, policy: rule });
        remaining.push({ ...finding, policyExpired: rule.expires });
        continue;
      }
    }
    allowed.push({ ...finding, policy: rule });
  }
  return { remaining, allowed, expired };
}

/** Build a starter policy from findings the user has decided to accept. */
export function renderPolicy(findings, { reason = "reviewed" } = {}) {
  return {
    allow: Object.fromEntries(findings.map((f) => [f.name, { reason, expires: null }])),
    failOn: "high",
  };
}
