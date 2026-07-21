# Code Redox

> **A desktop code-health workbench that helps developers find, understand, and safely reduce codebase drift—with Codex on hand when a finding needs a focused repair.**

**Hackathon track:** Developer Tools<br>
**Platform:** Windows 10/11 (64-bit)<br>
**Built with:** Electron, Node.js, **Codex**, and **GPT-5.6**.

[Download the Windows installer](https://github.com/withinJoel/CodeRedox/releases) · [Report an issue](https://github.com/withinJoel/CodeRedox/issues)

## Why Code Redox?

As a project grows, small compromises pile up: duplicate logic, stale TODOs, unused dependencies, unsafe patterns, and complex files that become difficult to change. Existing tools often surface isolated warnings; Code Redox brings those signals into one local desktop workflow and adds the context needed to decide what to do next.

Open any repository, run an audit, inspect the exact files and lines involved, trace a finding to the commit that introduced it, and—when appropriate—delegate a narrowly scoped fix to Codex. Every Codex fix is re-scanned so the result is visible and reviewable.

## What it does

- Runs configurable checks across foundations, maintainability, reliability, security, runtime safety, and accessibility.
- Flags **Formatting Drift** with Prettier when machine-edited JavaScript, TypeScript, JSON, CSS, HTML, Vue, or YAML files no longer match the project’s readable formatting; users can apply the repository-aware formatter directly and re-scan.
- Detects whitespace issues, debug code, TODO debt, dead code, duplicate code, large/long/complex functions, magic values, empty artifacts, and more.
- Surfaces static signals for common security and reliability risks, including hard-coded secrets, unsafe dynamic operations, weak cryptography, insecure randomness, injection sinks, path traversal, unsafe deserialization, regex DoS, cookie issues, and TLS validation.
- Builds a project overview with language mix, repository health signals, contributors, Git activity, a quality score, and finding breakdowns.
- Provides a **Time Machine** view that links current findings to the Git commits that last changed their lines.
- Creates an evidence-based **Forecast** of maintenance hotspots from scan findings, dependency signals, and recent Git change frequency.
- Adds **Codebase Rescue Mode**: a guided before/after story that captures a health baseline, gates ship readiness, traces risk through Git, recommends the one highest-impact change, verifies a Codex repair, and produces a shareable handoff brief.
- Adds **Repair Flight Plan**: before authorizing a Codex repair, Code Redox builds a local evidence-backed preflight for the selected finding its likely blast radius, Git churn, behavior-preservation contract, allowed file scope, verification commands, and review gates. The approved plan is passed into the focused Codex task and the result is re-scanned.
- Produces a **Repair Receipt** after an approved Flight Plan runs: it compares the Git working-tree change set against the allowed scope and pairs that evidence with the fresh scan outcome. A clean baseline makes the receipt an isolated, reviewable proof of agent adherence.
- Shows a **Decision Lens** on every finding: priority rank, risk tier, same-file pressure, repeated-pattern count, release posture, and project health with the heuristic disclosed so developers can make an informed review decision.
- Includes **Fix Ripple**, an interactive no-write simulation that previews how resolving one finding changes active findings, maintenance drag, high-risk signals, file pressure, and the next best focus before a user authorizes a repair.
- Adds **Redox Gate**, a pre-merge passport for the current Git working tree: it maps changed files, intersects them with current scan findings, highlights sensitive surfaces, suggests the project’s verification route, and gives an explainable **Awaiting Diff / Hold / Review / Clear to Review** posture. It is intentionally evidence for a human merge decision—not a replacement for testing or review.
- Audits supported dependency manifests, checks public registry versions, identifies duplicate declarations/capability overlap and apparent unused packages, and can update or uninstall packages from the UI.
- Turns codebase superlatives into an interactive **Hall of Fame**: click an Award to spotlight the source structure, see nearby scan evidence, and jump to the relevant finding when action is warranted.
- Offers a repository-aware **Codex chat** in read-only *Ask* mode or explicit write-authorized *Work* mode.
- Sends individual findings or all findings in one check to Codex using focused, generated task instructions; Code Redox streams progress and rescans afterward.

### Supported project inputs

Code Redox scans local folders and understands source files across JavaScript/TypeScript, Python, Java, Go, Rust, PHP, C#, Kotlin, Swift, HTML/CSS, and other common extensions. Dependency inspection supports:

- npm (`package.json`)
- Composer (`composer.json`)
- Maven (`pom.xml`) and Gradle
- Python requirements files
- Go modules (`go.mod`)
- Rust (`Cargo.toml`)

Git-powered features require the opened folder to be a Git repository with available history. Package version lookups require an internet connection.

## Install and run

### Recommended: Windows installer

1. Open the [GitHub Releases page](https://github.com/withinJoel/CodeRedox/releases).
2. Download the latest `Code Redox Setup <version>.exe` asset.
3. Run the installer and accept the Windows security prompt if shown.
4. Start **Code Redox** from the Start menu, then choose the local project folder to audit.

The installer is the quickest way for judges to test the app without rebuilding it. It bundles the Electron app and its analysis dependencies.

### To use Codex-powered actions

Code Redox can scan repositories without Codex. To use **Fix via Codex** or the **Chat** tab, install and sign in to the current [Codex CLI](https://developers.openai.com/codex/cli/). Ensure `codex` is available on your `PATH`; alternatively, set `CODEX_CLI_PATH` to the absolute path of the Codex executable. The application runs Codex in the folder you opened and uses the model configured by that CLI; it does not select a model itself.

Before using a write action, commit or otherwise back up the target repository. Code Redox narrows the prompt to the selected finding(s), but the resulting code change remains yours to inspect, test, and commit.

### Build from source

Prerequisites:

- Node.js 20 or later
- npm
- Windows 10/11 for the packaged desktop build
- Codex CLI only for Codex chat/fix functionality

```bash
git clone https://github.com/withinJoel/CodeRedox.git
cd CodeRedox
npm ci
npm start
```

Run the automated tests:

```bash
npm test
```

Create a Windows NSIS installer:

```bash
npm run package
```

Electron Builder writes the release artifacts to `dist/`. Upload the generated `Code Redox Setup <version>.exe` file to a GitHub Release. The unpacked directory is useful for local testing but is not the preferred distribution artifact.

## Quick judge/test flow

1. Install the release executable, launch Code Redox, and select this repository or another small Git repository.
2. Let the initial analysis finish; browse **Overview** and **Findings**.
3. Open a finding to see the file, line, reason, and—on Git-backed projects—its line-history commit and diff.
4. Make a small local change, then open **Redox Gate** to see the Git diff, scan intersection, sensitive paths, and suggested human verification route.
5. Explore **Time Machine**, **Forecast**, **Packages**, and **Awards**.
6. If Codex CLI is installed, select a low-risk finding such as whitespace or debug code and choose **Fix via Codex**. Watch the live activity and the automatic re-scan, then inspect the resulting diff in the target repository.

### Judge-ready 60-second demo

1. Open a deliberately imperfect Git repository and select **Rescue**.
2. Choose **Start live rescue** to capture the Redox Index, finding count, maintenance-drag estimate, and Git/forecast evidence.
3. Show the **Ship Readiness Gate** and **One-Change Challenge**, then open the recommended finding.
4. Choose **Create flight plan** to reveal the local blast-radius map, behavior contract, test route, and scope gates; then choose **Approve & run this plan**.
5. Open **Redox Gate** to turn that resulting Git diff into a memorable pre-merge passport: diff map, linked scan evidence, release posture, and the verification route that still needs a human.
6. Return to Rescue to show the **Repair Receipt**: plan adherence, changed files, and the verified re-scan outcome; then copy the **Team Handoff Brief**.

This tells the full product story in one pass: find risk, understand its history, preview a safe AI repair, fix it with explicit constraints, and prove the outcome.

## Hackathon implementation: Codex + GPT-5.6

**GPT-5.6 was the primary implementation collaborator used through Codex during this hackathon.** It was used for more than isolated code completion: it helped take Code Redox from a code-health scanner to a complete, testable Windows developer-tool workflow. The builder set the product direction, reviewed the generated work, and made the final product and engineering decisions; Codex accelerated the exploration, implementation, and iteration.

### Where Codex accelerated the workflow

- **From idea to an end-to-end workflow:** Working with GPT-5.6 in Codex helped refine the original “AI coding slop” idea into the shipped flow: scan a local repository, explain the evidence, map history and likely future pressure, preview the repair, require explicit approval, verify the result, and hand the outcome back to a team.
- **Multi-file Electron implementation:** Codex accelerated work across the Electron main process, context-isolated preload bridge, renderer UI, static-analysis workers, Git integration, caching, package inspection, and tests. This made it practical to iterate on a desktop experience while preserving clear boundaries between the UI and local filesystem access.
- **Evidence before agent action:** GPT-5.6 helped design and implement Rescue Mode, Decision Lens, Fix Ripple, Repair Flight Plan, Repair Receipt, and Redox Gate. These features were deliberate product decisions: before an AI repair is approved, the developer sees local blast radius, file scope, Git churn, behavior constraints, verification commands, and an explicit human review gate.
- **Focused Codex repair loop:** For a repair, Code Redox creates a temporary task containing only the selected finding and, when approved, its Flight Plan constraints. It invokes `codex exec`, streams the activity into the app, removes the temporary file, re-scans the repository, and can compare the resulting Git change set with the allowed scope. GPT-5.6 and Codex made this constrained, reviewable agent workflow feasible to build and iterate quickly.
- **Quality and release hardening:** Codex accelerated regression-test coverage for analysis helpers, safer filesystem cleanup, output normalization for third-party tools, concurrency improvements, formatting-drift repair, and the Windows packaging path. The builder validated behavior with tests and reviewed the release workflow.

### Key decisions made by the builder

- **Local-first by default:** Code Redox analyzes the folder chosen by the developer; findings, Git context, and evidence stay in the local workflow.
- **No silent writes:** Chat has a read-only Ask mode. Work mode and every repair require an explicit user action; formatting has its own explicit Prettier action.
- **Evidence, not certainty:** Static findings, forecasts, and Redox Gate are presented as explainable evidence for a human decision—not claims that code is safe or that a future failure is guaranteed.
- **Constrain, then verify:** The Flight Plan deliberately limits an AI task before it runs, while the Receipt, re-scan, Git diff, and suggested test route make post-change review concrete.

### GPT-5.6 in the shipped experience

The hackathon build work used GPT-5.6 through Codex. At runtime, Code Redox delegates repository chat and repair requests to the model configured in the user’s local Codex CLI; the app does not silently select or override that model. This keeps model access and authorization with the developer while preserving the focused workflow built with Codex and GPT-5.6.

> **Codex feedback session:** 019f7ae4-892a-7aa1-8915-cb685a145493

## Architecture

```text
Electron renderer
  └─ Context-isolated preload IPC bridge
      └─ Main-process ProjectService
          ├─ Built-in static analysis workers
          ├─ Knip, JSCPD, and slop-scan integrations
          ├─ Git metadata, blame, log, and diff analysis
          ├─ Package manifest and registry inspection
          └─ Codex CLI (explicit chat/fix requests only)
```

Code Redox excludes common generated/vendor locations such as `node_modules`, `.git`, `dist`, `build`, `.next`, and `coverage` from source scanning. Scan results are cached per opened project and invalidated when the source fingerprint or enabled-check configuration changes.

## Important notes

- Code Redox provides **static-analysis signals**, not a security certification or a replacement for code review, testing, dependency policy, or professional security assessment.
- The app reads and analyzes the local folder selected by the user. It accesses the network for public package-registry lookups, public GitHub contributor data when the opened project has a GitHub remote, and when the user deliberately invokes Codex through their configured CLI.
- Package usage detection is heuristic and based on static imports/references; verify a dependency before removing it.
- Git features degrade gracefully when a project has no repository history.
- Do not open untrusted repositories with write-authorized Codex actions unless you have reviewed the scope and have a backup or commit to return to.

## Repository layout

```text
src/main/       Electron process, repository services, analysis orchestration
src/preload/    Context-isolated renderer API
src/renderer/   Desktop UI
test/           Node test suite
Logo/           Application assets
```

## License and contribution

MIT License.

---

Made with care by Joel Jolly.
