# Code Redox

> **A desktop code-health workbench that helps developers find, understand, and safely reduce codebase drift—with Codex on hand when a finding needs a focused repair.**

**Hackathon track:** Developer Tools<br>
**Platform:** Windows 10/11 (64-bit)<br>
**Built with:** Electron, Node.js, Codex, and GPT-5.6

[Download the Windows installer](https://github.com/withinJoel/CodeRedox/releases) · [Report an issue](https://github.com/withinJoel/CodeRedox/issues)

## Why Code Redox?

As a project grows, small compromises pile up: duplicate logic, stale TODOs, unused dependencies, unsafe patterns, and complex files that become difficult to change. Existing tools often surface isolated warnings; Code Redox brings those signals into one local desktop workflow and adds the context needed to decide what to do next.

Open any repository, run an audit, inspect the exact files and lines involved, trace a finding to the commit that introduced it, and—when appropriate—delegate a narrowly scoped fix to Codex. Every Codex fix is re-scanned so the result is visible and reviewable.

## What it does

- Runs **30 configurable checks** across foundations, maintainability, reliability, security, runtime safety, and accessibility.
- Detects whitespace issues, debug code, TODO debt, dead code, duplicate code, large/long/complex functions, magic values, empty artifacts, and more.
- Surfaces static signals for common security and reliability risks, including hard-coded secrets, unsafe dynamic operations, weak cryptography, insecure randomness, injection sinks, path traversal, unsafe deserialization, regex DoS, cookie issues, and TLS validation.
- Builds a project overview with language mix, repository health signals, contributors, Git activity, a quality score, and finding breakdowns.
- Provides a **Time Machine** view that links current findings to the Git commits that last changed their lines.
- Creates an evidence-based **Forecast** of maintenance hotspots from scan findings, dependency signals, and recent Git change frequency.
- Adds **Codebase Rescue Mode**: a guided before/after story that captures a health baseline, gates ship readiness, traces risk through Git, recommends the one highest-impact change, verifies a Codex repair, and produces a shareable handoff brief.
- Adds **Repair Flight Plan**: before authorizing a Codex repair, Code Redox builds a local evidence-backed preflight for the selected findingâ€”its likely blast radius, Git churn, behavior-preservation contract, allowed file scope, verification commands, and review gates. The approved plan is passed into the focused Codex task and the result is re-scanned.
- Produces a **Repair Receipt** after an approved Flight Plan runs: it compares the Git working-tree change set against the allowed scope and pairs that evidence with the fresh scan outcome. A clean baseline makes the receipt an isolated, reviewable proof of agent adherence.
- Audits supported dependency manifests, checks public registry versions, identifies duplicate declarations/capability overlap and apparent unused packages, and can update or uninstall packages from the UI.
- Gives the codebase playful “Awards” to reveal its largest files/functions, most-commented areas, and debugging hotspots.
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

Code Redox can scan repositories without Codex. To use **Fix via Codex** or the **Chat** tab, install and sign in to the current [Codex CLI](https://developers.openai.com/codex/cli/), with access to GPT-5.6. Ensure `codex` is available on your `PATH`; alternatively, set `CODEX_CLI_PATH` to the absolute path of the Codex executable. The application runs Codex in the folder you opened.

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
4. Explore **Time Machine**, **Forecast**, **Packages**, and **Awards**.
5. If Codex CLI is installed, select a low-risk finding such as whitespace or debug code and choose **Fix via Codex**. Watch the live activity and the automatic re-scan, then inspect the resulting diff in the target repository.

### Judge-ready 60-second demo

1. Open a deliberately imperfect Git repository and select **Rescue**.
2. Choose **Start live rescue** to capture the Redox Index, finding count, maintenance-drag estimate, and Git/forecast evidence.
3. Show the **Ship Readiness Gate** and **One-Change Challenge**, then open the recommended finding.
4. Choose **Create flight plan** to reveal the local blast-radius map, behavior contract, test route, and scope gates; then choose **Approve & run this plan**.
5. Return to Rescue to show the **Repair Receipt**: plan adherence, changed files, and the verified re-scan outcome; then copy the **Team Handoff Brief**.

This tells the full product story in one pass: find risk, understand its history, preview a safe AI repair, fix it with explicit constraints, and prove the outcome.

## How Codex and GPT-5.6 shaped the project

This project was built during the hackathon with Codex using GPT-5.6 as the core implementation collaborator. The collaboration was used to move quickly from product exploration to a testable Windows desktop application:

- **Product and UX iteration:** Codex helped turn the broad idea of “AI coding slop” into a practical workflow: scan, understand context, decide, make a focused change, and verify with a re-scan. The final product decisions—local-first scanning, per-check controls, Git context, and explicit write authorization—were made to keep developers in control.
- **Engineering acceleration:** Codex helped implement the Electron main/preload/renderer split, safe IPC boundaries, concurrent scan orchestration, caching, Git history views, dependency discovery across ecosystems, and the test suite.
- **Focused repair workflow:** GPT-5.6 is accessed through the user’s Codex CLI for repository chat and repair tasks. Code Redox writes a temporary, narrowly scoped task file for the selected finding(s), invokes `codex exec`, streams status into the UI, removes the task file afterward, and re-scans the project. Ask mode uses a read-only sandbox; Work mode requires explicit user authorization.
- **Quality decisions:** Codex was used to refine prompt templates for safe minimal edits, add guards around filesystem cleanup, normalize third-party tool output, and add regression coverage for the analysis helpers.

The human builder directed the feature scope, decided which automation should be opt-in, reviewed code and test behavior, and chose the final design and release path.

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
- The app reads and analyzes the local folder selected by the user. It accesses the network only for public package-registry lookups and when the user deliberately invokes Codex through their configured CLI.
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
