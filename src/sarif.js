const VERSION_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

const LEVEL = { high: "error", medium: "warning", low: "note" };

const RULE_TEXT = {
  "pipe-to-shell": "Install hook downloads and executes a remote script in one step.",
  "obfuscated-exec": "Install hook evaluates code at runtime (eval/atob/base64/child_process).",
  "credential-exfil": "Install hook reads credentials or environment and contacts the network.",
  "network-download": "Install hook fetches content from the internet.",
  "download-exec": "Install hook downloads content and executes a process in the same script.",
  "env-read": "Install hook reads a sensitive environment variable.",
  "shell-exec": "Install hook shells out.",
  "path-escape": "Install hook points at a file outside its own package directory.",
  "native-build": "Install hook performs a native compile step.",
  "script-exec": "Install hook runs a JavaScript file from the package.",
  "git-dependency": "Dependency is installed from git, so its prepare script runs on install and its ref can change under you.",
  "funding-nag": "Install hook prints a funding message.",
  other: "Install hook runs an unrecognised command.",
};

function rule(category) {
  return {
    id: `installguard/${category}`,
    name: category.replace(/(^|-)([a-z])/g, (_, __, c) => c.toUpperCase()),
    shortDescription: { text: RULE_TEXT[category] ?? RULE_TEXT.other },
    fullDescription: { text: `${RULE_TEXT[category] ?? RULE_TEXT.other} Install scripts execute with your privileges the moment a dependency is installed.` },
    help: {
      text: "Review the hook. `installguard allow --write` blocks install scripts except genuine native builds; record deliberate exceptions in .installguardrc.json.",
    },
    properties: { tags: ["supply-chain", "security", "npm"] },
  };
}

/**
 * Render findings as SARIF 2.1.0 so they land in GitHub's Security tab (or any
 * SARIF-consuming tool) instead of scrolling past in a CI log.
 *
 * Locations point at the package's own manifest, and — when deep inspection
 * found something — at the exact line of the install script file, which is what
 * makes the annotation reviewable rather than merely present.
 */
export function toSarif(findings, { toolVersion = "0.0.0", lockfile = null } = {}) {
  const categories = new Set();
  const results = [];

  for (const finding of findings) {
    for (const script of finding.scripts ?? []) {
      categories.add(script.category);
      const manifest = finding.path ? `${finding.path}/package.json` : lockfile ?? "package.json";
      const locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: manifest.split("\\").join("/") },
            region: { startLine: 1 },
          },
        },
      ];
      for (const e of script.evidence ?? []) {
        locations.push({
          physicalLocation: {
            artifactLocation: { uri: `${finding.path}/${script.sourceFile}`.split("\\").join("/") },
            region: { startLine: e.line, snippet: { text: e.text } },
          },
          message: { text: `${e.category}: ${e.text}` },
        });
      }
      results.push({
        ruleId: `installguard/${script.category}`,
        level: LEVEL[script.risk] ?? "warning",
        message: {
          text: `${finding.name}@${finding.version ?? "?"} runs "${script.command}" on ${script.hook} [${script.category}]`,
        },
        locations,
        partialFingerprints: { installguardHook: `${finding.name}:${script.hook}:${script.command}` },
        properties: { package: finding.name, version: finding.version ?? null, hook: script.hook, risk: script.risk },
      });
    }
  }

  return {
    $schema: VERSION_URI,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "installguard",
            informationUri: "https://github.com/Nom-nom-hub/installguard",
            version: toolVersion,
            rules: [...categories].sort().map(rule),
          },
        },
        results,
      },
    ],
  };
}
