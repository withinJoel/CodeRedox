import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import { app } from 'electron';
import ignore from 'ignore';
import MarkdownIt from 'markdown-it';
import sanitizeHtml from 'sanitize-html';
import simpleGit from 'simple-git';
import { buildPrompt } from './prompts.js';
import { addLatestVersions, discoverPackages, managePackage } from './package-service.js';
import { deleteEmptyArtifact, findEmptyArtifacts } from './empty-artifact-service.js';

const EXCLUDED = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);
const SCAN_VERSION = 9;
const LANGUAGE_BY_EXTENSION = {
  js: ['JavaScript', '#f1e05a'], mjs: ['JavaScript', '#f1e05a'], cjs: ['JavaScript', '#f1e05a'],
  ts: ['TypeScript', '#3178c6'], tsx: ['TypeScript', '#3178c6'], jsx: ['JavaScript', '#f1e05a'],
  py: ['Python', '#3572A5'], rs: ['Rust', '#dea584'], go: ['Go', '#00ADD8'], java: ['Java', '#b07219'],
  css: ['CSS', '#563d7c'], html: ['HTML', '#e34c26'], vue: ['Vue', '#41b883'], rb: ['Ruby', '#701516'],
  php: ['PHP', '#4F5D95'], swift: ['Swift', '#F05138'], kt: ['Kotlin', '#A97BFF'], cs: ['C#', '#178600'],
  cpp: ['C++', '#f34b7d'], c: ['C', '#555555'], md: ['Markdown', '#083fa1'], json: ['JSON', '#292929'], sh: ['Shell', '#89e051']
};
const CHECKS = [
  { id: 'whitespace', label: 'Whitespace', command: 'built-in', group: 'Foundations' },
  { id: 'debug-code', label: 'Debug Code', command: 'built-in', group: 'Foundations' },
  { id: 'todo-debt', label: 'TODO Debt', command: 'built-in', group: 'Foundations' },
  { id: 'dead-code', label: 'Dead Code', command: 'knip', group: 'Clean code' },
  { id: 'duplicate-code', label: 'Duplicate Code', command: 'jscpd', group: 'Clean code' },
  { id: 'magic-values', label: 'Magic Values', command: 'built-in', group: 'Clean code' },
  { id: 'empty-artifacts', label: 'Empty Files & Folders', command: 'built-in', group: 'Project cleanup' },
  { id: 'long-functions', label: 'Long Functions', command: 'built-in', group: 'Maintainability' },
  { id: 'large-files', label: 'Large Source Files', command: 'built-in', group: 'Maintainability' },
  { id: 'parameter-bloat', label: 'Parameter Bloat', command: 'built-in', group: 'Maintainability' },
  { id: 'nested-ternaries', label: 'Nested Ternaries', command: 'built-in', group: 'Maintainability' },
  { id: 'complex-logic', label: 'Complex Logic', command: 'built-in', group: 'Maintainability' },
  { id: 'logic-conditions', label: 'Logic Conditions', command: 'built-in', group: 'Reliability' },
  { id: 'error-handling', label: 'Error Handling', command: 'built-in', group: 'Reliability' },
  { id: 'secrets', label: 'Secrets', command: 'built-in', group: 'Security' },
  { id: 'weak-cryptography', label: 'Weak Cryptography', command: 'built-in', group: 'Security' },
  { id: 'insecure-randomness', label: 'Insecure Randomness', command: 'built-in', group: 'Security' },
  { id: 'unvalidated-redirects', label: 'Unvalidated Redirects', command: 'built-in', group: 'Security' },
  { id: 'sql-injection', label: 'SQL Injection', command: 'built-in', group: 'Security' },
  { id: 'path-traversal', label: 'Path Traversal', command: 'built-in', group: 'Security' },
  { id: 'xss-sinks', label: 'XSS Sinks', command: 'built-in', group: 'Security' },
  { id: 'tls-validation', label: 'TLS Validation', command: 'built-in', group: 'Security' },
  { id: 'unsafe-deserialization', label: 'Unsafe Deserialization', command: 'built-in', group: 'Security' },
  { id: 'regex-dos', label: 'Regex DoS', command: 'built-in', group: 'Security' },
  { id: 'insecure-cookies', label: 'Insecure Cookies', command: 'built-in', group: 'Security' },
  { id: 'unsafe-operations', label: 'Unsafe Operations', command: 'built-in', group: 'Runtime safety' },
  { id: 'package-integrity', label: 'Package Integrity', command: 'slop-scan', group: 'Runtime safety' },
  { id: 'deprecated-apis', label: 'Deprecated APIs', command: 'built-in', group: 'Maintainability' },
  { id: 'unsafe-external-links', label: 'Unsafe External Links', command: 'built-in', group: 'Accessibility' },
  { id: 'image-alt-text', label: 'Image Alt Text', command: 'built-in', group: 'Accessibility' }
];

const escapeHtml = (value = '') => String(value).replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
const sha = value => crypto.createHash('sha256').update(value).digest('hex').slice(0, 16);

export class ProjectService {
  constructor({ store, send }) { this.store = store; this.send = send; this.projects = new Map(); this.issues = new Map(); }

  async open(projectPath) {
    const root = path.resolve(projectPath);
    const stat = await fs.stat(root);
    if (!stat.isDirectory()) throw new Error('Please choose a folder.');
    const id = sha(root);
    const cached = await this.readCache(id);
    const files = await listFiles(root);
    const metadata = await collectMetadata(root, files);
    const disabledChecks = this.disabledChecksFor(id);
    const project = { id, path: root, name: path.basename(root), files, metadata, cached, disabledChecks };
    this.projects.set(id, project);
    this.addRecent(project);
    if (cached?.results) this.indexIssues(cached.results, project.id);
    return { id, name: project.name, path: root, metadata, checks: CHECKS, disabledChecks, cachedResults: cached?.results ?? null, lastScan: cached?.lastScan ?? null };
  }

  async startScan(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before scanning it.');
    const fingerprint = await fileFingerprint(project.files);
    const checkConfigSignature = [...project.disabledChecks].sort().join('|');
    if (project.cached?.scanVersion === SCAN_VERSION && project.cached?.checkConfigSignature === checkConfigSignature && project.cached?.fingerprint === fingerprint && project.cached?.results) {
      this.send('scan:progress', { projectId, checkId: 'all', status: 'done', cached: true });
      this.send('scan:results', { projectId, results: project.cached.results, cached: true, fixedCount: project.cached.fixedCount || 0 });
      return { cached: true, results: project.cached.results, fixedCount: project.cached.fixedCount || 0 };
    }
    CHECKS.forEach(check => {
      const disabled = project.disabledChecks.includes(check.id);
      this.progress(projectId, check.id, disabled ? 'disabled' : 'pending', 0);
      this.send('scan:results', { projectId, checkId: check.id, issues: [], reset: true });
    });
    const runners = {
      'dead-code': () => this.runKnip(project),
      'duplicate-code': () => this.runJscpd(project),
      whitespace: () => this.runWhitespace(project),
      'debug-code': () => this.runCodeQuality(project, 'debug-code'),
      'todo-debt': () => this.runCodeQuality(project, 'todo-debt'),
      'magic-values': () => this.runCodeQuality(project, 'magic-values'),
      'empty-artifacts': () => this.runEmptyArtifacts(project),
      'long-functions': () => this.runCodeQuality(project, 'long-functions'),
      'large-files': () => this.runCodeQuality(project, 'large-files'),
      'parameter-bloat': () => this.runCodeQuality(project, 'parameter-bloat'),
      'nested-ternaries': () => this.runCodeQuality(project, 'nested-ternaries'),
      'complex-logic': () => this.runCodeQuality(project, 'complex-logic'),
      'logic-conditions': () => this.runCodeQuality(project, 'logic-conditions'),
      'error-handling': () => this.runCodeQuality(project, 'error-handling'),
      secrets: () => this.runCodeQuality(project, 'secrets'),
      'weak-cryptography': () => this.runCodeQuality(project, 'weak-cryptography'),
      'insecure-randomness': () => this.runCodeQuality(project, 'insecure-randomness'),
      'unvalidated-redirects': () => this.runCodeQuality(project, 'unvalidated-redirects'),
      'sql-injection': () => this.runCodeQuality(project, 'sql-injection'),
      'path-traversal': () => this.runCodeQuality(project, 'path-traversal'),
      'xss-sinks': () => this.runCodeQuality(project, 'xss-sinks'),
      'tls-validation': () => this.runCodeQuality(project, 'tls-validation'),
      'unsafe-deserialization': () => this.runCodeQuality(project, 'unsafe-deserialization'),
      'regex-dos': () => this.runCodeQuality(project, 'regex-dos'),
      'insecure-cookies': () => this.runCodeQuality(project, 'insecure-cookies'),
      'unsafe-operations': () => this.runCodeQuality(project, 'unsafe-operations'),
      'package-integrity': () => this.runPackageIntegrity(project),
      'deprecated-apis': () => this.runCodeQuality(project, 'deprecated-apis'),
      'unsafe-external-links': () => this.runCodeQuality(project, 'unsafe-external-links'),
      'image-alt-text': () => this.runCodeQuality(project, 'image-alt-text')
    };
    let scanHadErrors = false;
    const activeChecks = CHECKS.filter(check => !project.disabledChecks.includes(check.id));
    const resultPairs = await Promise.all(activeChecks.map(async check => {
      this.progress(projectId, check.id, 'running');
      try {
        const issues = await runners[check.id]();
        this.progress(projectId, check.id, 'done', issues.length);
        this.send('scan:results', { projectId, checkId: check.id, issues });
        return [check.id, issues];
      } catch (error) {
        scanHadErrors = true;
        this.progress(projectId, check.id, 'error', 0, error.message);
        return [check.id, []];
      }
    }));
    const resultMap = Object.fromEntries(resultPairs);
    const results = Object.fromEntries(CHECKS.map(check => [check.id, resultMap[check.id] || []]));
    const previousIds = new Set(activeChecks.flatMap(check => project.cached?.results?.[check.id] || []).map(issue => issue.id));
    const currentIds = new Set(activeChecks.flatMap(check => results[check.id]).map(issue => issue.id));
    const fixedCount = [...previousIds].filter(id => !currentIds.has(id)).length;
    if (!scanHadErrors) {
      project.cached = { scanVersion: SCAN_VERSION, checkConfigSignature, fingerprint, lastScan: new Date().toISOString(), results, fixedCount };
      await this.writeCache(projectId, project.cached);
    }
    this.indexIssues(results, project.id);
    this.send('scan:results', { projectId, results, complete: true, fixedCount, incomplete: scanHadErrors });
    return { cached: false, results, fixedCount, incomplete: scanHadErrors };
  }

  async getPackages(projectId, force = false) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before viewing its packages.');
    const cacheAge = Date.now() - (project.packages?.fetchedAt || 0);
    if (!force && project.packages && cacheAge < 5 * 60 * 1000) return project.packages;
    const declared = await discoverPackages(project.path, project.files);
    const packages = await addLatestVersions(declared);
    project.packages = { packages, fetchedAt: Date.now() };
    return project.packages;
  }
  async managePackage(projectId, packageId, action) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before changing a package.');
    const packageInfo = await this.getPackages(projectId);
    const item = packageInfo.packages.find(candidate => candidate.id === packageId);
    if (!item) throw new Error('That package is no longer available. Refresh the Packages tab and try again.');
    const result = await managePackage(project.path, project.files, item, action);
    project.packages = null;
    return result;
  }
  async getOverview(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before viewing its overview.');
    if (project.overview) return project.overview;
    const [githubContributors, packages] = await Promise.all([getGitHubContributors(project.metadata.git.remote), discoverPackages(project.path, project.files)]);
    project.overview = { contributors: githubContributors.length ? githubContributors : project.metadata.git.contributors, packages: { count: packages.length, ecosystems: [...new Set(packages.map(item => item.ecosystem))] } };
    return project.overview;
  }
  async deleteEmptyArtifact(projectId, issueId) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.type !== 'empty-artifacts') throw new Error('That empty item is no longer available.');
    await deleteEmptyArtifact(project.path, issue.file, issue.kind);
    project.cached = null;
    this.issues.delete(issueId);
    return { issueId };
  }
  async fixViaCodex(projectId, issueId) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.projectId !== projectId) throw new Error('That finding is no longer available.');
    const taskFile = `.coderedox-codex-task-${crypto.randomUUID()}.md`;
    const taskPath = path.join(project.path, taskFile);
    const task = `# CodeRedox single-finding fix task\n\nFix only the finding below. Work only on files required by it, preserve project conventions, do not change unrelated code, and verify the fix before finishing.\n\n## Finding\n${buildPrompt(issue)}`;
    await fs.writeFile(taskPath, task, { encoding: 'utf8', flag: 'wx' });
    try {
      await runCodexCli(project.path, `Read ${taskFile} in the current project and complete the requested fix. Do not change unrelated code.`, event => this.send('codex:progress', { projectId, ...event }));
    } finally {
      await fs.unlink(taskPath).catch(() => {});
    }
    project.cached = null;
    return { message: 'Codex completed the requested fix.' };
  }
  async fixCheckViaCodex(projectId, checkId, issueIds = []) {
    const project = this.projects.get(projectId);
    const check = CHECKS.find(item => item.id === checkId);
    if (!project || !check) throw new Error('That finding section is no longer available.');
    if (project.disabledChecks.includes(checkId)) throw new Error(`${check.label} is disabled for this project.`);
    const requestedIds = new Set(issueIds);
    const issues = [...this.issues.values()].filter(issue => issue.projectId === projectId && issue.type === checkId && requestedIds.has(issue.id));
    if (!issues.length) throw new Error(`There are no current ${check.label.toLowerCase()} findings to fix.`);
    const taskFile = `.coderedox-codex-task-${crypto.randomUUID()}.md`;
    const taskPath = path.join(project.path, taskFile);
    const task = `# CodeRedox bulk fix task\n\nFix every ${check.label} finding listed below. Work only on files required by these findings, preserve project conventions, and verify the fixes before finishing.\n\n${issues.map((issue, index) => `## Finding ${index + 1}\n${buildPrompt(issue)}`).join('\n\n')}`;
    await fs.writeFile(taskPath, task, { encoding: 'utf8', flag: 'wx' });
    try {
      await runCodexCli(project.path, `Read ${taskFile} in the current project and complete every requested fix. Do not change unrelated code.`, event => this.send('codex:progress', { projectId, ...event }));
    } finally {
      await fs.unlink(taskPath).catch(() => {});
    }
    project.cached = null;
    return { message: `Codex completed ${issues.length} ${check.label.toLowerCase()} fixes.` };
  }

  progress(projectId, checkId, status, count, error) { this.send('scan:progress', { projectId, checkId, status, count, error }); }
  setCheckActive(projectId, checkId, active) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before changing its checks.');
    if (!CHECKS.some(check => check.id === checkId)) throw new Error('Unknown check.');
    const disabled = new Set(project.disabledChecks);
    active ? disabled.delete(checkId) : disabled.add(checkId);
    project.disabledChecks = [...disabled];
    const settings = this.store.get('disabledChecksByProject', {});
    this.store.set('disabledChecksByProject', { ...settings, [projectId]: project.disabledChecks });
    return { disabledChecks: project.disabledChecks };
  }
  getFixPrompt(issueId) { const issue = this.issues.get(issueId); if (!issue) throw new Error('That issue is no longer available.'); return buildPrompt(issue); }
  async getIssueCommit(projectId, issueId) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.projectId !== projectId) throw new Error('That finding is no longer available.');
    const git = simpleGit(project.path);
    let blame;
    try { blame = await git.raw(['blame', '--line-porcelain', '-L', `${issue.line},${issue.line}`, '--', issue.file]); }
    catch { throw new Error('Git cannot identify a commit for this finding. The file may be untracked, generated, or outside Git history.'); }
    const hash = blame.match(/^([0-9a-f]{40})\s/m)?.[1];
    if (!hash || /^0+$/.test(hash)) throw new Error('Git cannot identify a commit for this finding.');
    const metadata = (await git.raw(['show', '-s', '--format=%H%x00%h%x00%an%x00%ae%x00%aI%x00%s', hash])).trim().split('\0');
    const files = (await git.raw(['show', '--format=', '--name-status', '--find-renames', hash])).trim().split(/\r?\n/).filter(Boolean).map(line => {
      const [status, ...paths] = line.split('\t'); return { status, path: paths.join(' → ') };
    });
    const fullPatch = await git.raw(['show', '--format=', '--patch', '--find-renames', '--no-ext-diff', hash]);
    const maxPatchLength = 750000;
    const additions = (fullPatch.match(/^\+(?!\+\+)/gm) || []).length;
    const deletions = (fullPatch.match(/^-(?!---)/gm) || []).length;
    return { hash: metadata[0], shortHash: metadata[1], author: metadata[2], email: metadata[3], date: metadata[4], subject: metadata[5], files, additions, deletions, file: issue.file, line: issue.line, patch: fullPatch.slice(0, maxPatchLength), truncated: fullPatch.length > maxPatchLength };
  }
  async highlight(issueId) {
    const issue = this.issues.get(issueId); if (!issue?.snippet) return '';
    try { const { codeToHtml } = await import('shiki'); return await codeToHtml(issue.snippet, { lang: shikiLanguage(issue.language), theme: 'github-light' }); }
    catch { return `<pre><code>${escapeHtml(issue.snippet)}</code></pre>`; }
  }
  indexIssues(results, projectId) { Object.values(results).flat().forEach(issue => { issue.projectId = projectId; this.issues.set(issue.id, issue); }); }
  addRecent(project) {
    const current = this.store.get('recentProjects', []).filter(item => item.path !== project.path);
    this.store.set('recentProjects', [{ id: project.id, name: project.name, path: project.path, lastOpened: new Date().toISOString() }, ...current].slice(0, 12));
  }
  disabledChecksFor(projectId) { return this.store.get('disabledChecksByProject', {})[projectId] || []; }
  cachePath(id) { return path.join(app.getPath('userData'), 'projects', `${id}.json`); }
  async readCache(id) { try { return JSON.parse(await fs.readFile(this.cachePath(id), 'utf8')); } catch { return null; } }
  async writeCache(id, data) { await fs.mkdir(path.dirname(this.cachePath(id)), { recursive: true }); await fs.writeFile(this.cachePath(id), JSON.stringify(data), 'utf8'); }

  issue(project, checkId, data) {
    const relativeFile = data.file ? data.file.replaceAll('\\', '/') : 'package.json';
    return { id: sha(`${project.id}:${checkId}:${relativeFile}:${data.line || 1}:${data.reason}`), type: checkId, file: relativeFile, line: data.line || 1, endLine: data.endLine || data.line || 1, reason: data.reason, symbol: data.symbol || '', snippet: data.snippet || '', kind: data.kind || '', language: languageFor(relativeFile) };
  }
  async runWhitespace(project) {
    const issues = [];
    await runProjectWorker('whitespace-worker.js', project, [], async line => {
      const event = safeJson(line, null);
      if (event?.type !== 'issue') return;
      const issue = this.issue(project, 'whitespace', { ...event.issue, snippet: await snippetAt(project.path, event.issue.file, event.issue.line) });
      issues.push(issue);
      this.send('scan:results', { projectId: project.id, checkId: 'whitespace', issues: [issue], append: true });
    });
    return issues;
  }
  async runCodeQuality(project, checkId) {
    const issues = [];
    await runProjectWorker('code-quality-worker.js', project, [checkId], async line => {
      const event = safeJson(line, null);
      if (event?.type !== 'issue') return;
      const snippet = checkId === 'secrets'
        ? await redactedSnippetAt(project.path, event.issue.file, event.issue.line)
        : await snippetAt(project.path, event.issue.file, event.issue.line);
      const issue = this.issue(project, checkId, { ...event.issue, snippet });
      issues.push(issue);
      this.send('scan:results', { projectId: project.id, checkId, issues: [issue], append: true });
    });
    return issues;
  }
  async runEmptyArtifacts(project) {
    const artifacts = await findEmptyArtifacts(project.path, project.files);
    return artifacts.map(artifact => this.issue(project, 'empty-artifacts', {
      ...artifact,
      line: 1,
      symbol: artifact.kind === 'folder' ? 'Empty folder' : 'Empty file',
      reason: artifact.kind === 'folder' ? 'Empty folder can be removed safely.' : 'Empty file can be removed safely.'
    }));
  }
  async runPackageIntegrity(project) {
    const executable = localBin('slop-scan');
    const scan = executable ? await run(executable, ['scan', '.', '--json'], { cwd: project.path }).catch(() => ({ stdout: '' })) : { stdout: '' };
    const candidates = parseSlopOutput(scan.stdout);
    const output = await runNodeScript('package-worker.js', [project.path]);
    candidates.push(...safeJson(output.stdout, []));
    return candidates.map(item => this.issue(project, 'package-integrity', item));
  }
  async runKnip(project) {
    const executable = localBin('knip');
    if (!executable) return [];
    const result = await run(executable, ['--reporter', 'json', '--no-progress', '--no-exit-code'], { cwd: project.path }).catch(error => ({ stdout: error.stdout || '', stderr: error.stderr || '' }));
    const json = safeJson(result.stdout, null);
    return normaliseKnip(json, project, (data) => this.issue(project, 'dead-code', data));
  }
  async runJscpd(project) {
    const executable = localBin('jscpd');
    if (!executable) return [];
    const reportDir = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-jscpd-'));
    try {
      await run(executable, ['--reporters', 'json', '--output', reportDir, '--silent', project.path], { cwd: project.path }).catch(() => null);
      const report = await findJson(reportDir);
      const duplicates = report?.duplicates ?? report?.json?.duplicates ?? [];
      return Promise.all(duplicates.flatMap(duplicate => [duplicate.firstFile, duplicate.secondFile].filter(Boolean).map(async location => this.issue(project, 'duplicate-code', {
        file: path.relative(project.path, location.name || location.path || '').replaceAll('\\', '/'), line: location.startLoc?.line || location.start || 1, endLine: location.endLoc?.line, reason: `Duplicated block (${duplicate.lines || 'multiple'} lines, ${duplicate.tokens || 'similar'} tokens).`, snippet: await snippetAt(project.path, path.relative(project.path, location.name || location.path || ''), location.startLoc?.line || 1)
      }))));
    } finally { await fs.rm(reportDir, { recursive: true, force: true }); }
  }
}

async function listFiles(root) {
  const ig = ignore();
  try { ig.add(await fs.readFile(path.join(root, '.gitignore'), 'utf8')); } catch { /* no .gitignore */ }
  const files = [];
  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      if (EXCLUDED.has(entry.name)) continue;
      const full = path.join(directory, entry.name); const relative = path.relative(root, full).replaceAll('\\', '/');
      if (ig.ignores(relative) && !isPotentialSecretFile(relative)) continue;
      if (entry.isDirectory()) await walk(full); else if (entry.isFile()) files.push({ full, relative, extension: path.extname(entry.name).slice(1).toLowerCase() });
    }
  }
  await walk(root); return files;
}
async function fileFingerprint(files) { const values = await Promise.all(files.map(async file => { const stat = await fs.stat(file.full); return `${file.relative}:${stat.mtimeMs}:${stat.size}`; })); return sha(values.sort().join('|')); }
async function collectMetadata(root, files) {
  const [readme, gitInfo, license] = await Promise.all([readReadme(root), getGitInfo(root), detectLicense(root)]);
  const languageTotals = new Map(); const topLevel = new Map(); const largestFiles = []; let size = 0;
  for (const file of files) { const stat = await fs.stat(file.full); size += stat.size; const language = LANGUAGE_BY_EXTENSION[file.extension]; if (language) languageTotals.set(language[0], (languageTotals.get(language[0]) || 0) + stat.size); const segment = file.relative.split('/')[0] || 'Root files'; topLevel.set(segment, (topLevel.get(segment) || 0) + 1); largestFiles.push({ path: file.relative, size: stat.size }); }
  const total = [...languageTotals.values()].reduce((a, b) => a + b, 0) || 1;
  const fallbackLanguages = [...languageTotals].sort((a, b) => b[1] - a[1]).map(([name, bytes]) => ({ name, percent: Math.round(bytes / total * 1000) / 10, color: Object.values(LANGUAGE_BY_EXTENSION).find(value => value[0] === name)?.[1] || '#8e8e93' }));
  const languages = await analyseLanguages(files, fallbackLanguages);
  return { readme, languages, license, git: gitInfo, signals: projectSignals(files, license), largestFiles: largestFiles.sort((left, right) => right.size - left.size).slice(0, 5), topLevel: [...topLevel].sort((left, right) => right[1] - left[1]).slice(0, 6).map(([name, count]) => ({ name, count })), size, fileCount: files.length };
}
async function analyseLanguages(files, fallback) {
  try {
    const linguist = (await import('linguist-js')).default;
    const sourceFiles = files.filter(file => file.extension && file.extension !== 'lock');
    const report = await linguist(sourceFiles.map(file => file.relative), { fileContent: await Promise.all(sourceFiles.map(file => fs.readFile(file.full, 'utf8').catch(() => ''))), offline: true, calculateLines: false });
    const entries = Object.entries(report.languages?.results || {}); const total = report.languages?.bytes || 1;
    return entries.sort((a, b) => b[1].bytes - a[1].bytes).map(([name, detail]) => ({ name, percent: Math.round(detail.bytes / total * 1000) / 10, color: detail.color || report.repository?.[name]?.color || '#8e8e93' }));
  } catch { return fallback; }
}
async function readReadme(root) {
  try {
    const entries = await fs.readdir(root);
    const readmeName = entries.find(name => /^readme(?:\.(?:md|markdown|mdown|mkdn))?$/i.test(name));
    if (!readmeName) throw new Error('No README found');
    const source = await fs.readFile(path.join(root, readmeName), 'utf8');
    const markdown = new MarkdownIt({ html: true, linkify: true, breaks: false, typographer: true });
    const image = markdown.renderer.rules.image || ((tokens, index, options, environment, self) => self.renderToken(tokens, index, options));
    markdown.renderer.rules.image = (tokens, index, options, environment, self) => {
      const src = tokens[index].attrGet('src');
      if (src && !/^(?:[a-z][a-z\d+.-]*:|#|\/)/i.test(src)) tokens[index].attrSet('src', pathToFileURL(path.resolve(root, src)).href);
      return image(tokens, index, options, environment, self);
    };
    const link = markdown.renderer.rules.link_open || ((tokens, index, options, environment, self) => self.renderToken(tokens, index, options));
    markdown.renderer.rules.link_open = (tokens, index, options, environment, self) => { tokens[index].attrSet('target', '_blank'); tokens[index].attrSet('rel', 'noopener noreferrer'); return link(tokens, index, options, environment, self); };
    const rendered = markdown.render(source).replace(/<li>\[([ xX])\]\s*/g, (_match, checked) => `<li class="task-list-item"><span class="task-box ${checked.toLowerCase() === 'x' ? 'checked' : ''}">${checked.toLowerCase() === 'x' ? '✓' : ''}</span>`);
    return sanitizeHtml(rendered, { allowedTags: [...sanitizeHtml.defaults.allowedTags, 'img', 'details', 'summary', 'sub', 'sup'], allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, '*': ['class', 'align', 'id'], a: ['href', 'name', 'target', 'rel'], img: ['src', 'srcset', 'alt', 'title', 'width', 'height', 'align'], code: ['class'] }, allowedSchemes: ['http', 'https', 'mailto', 'file', 'data'], allowedSchemesByTag: { img: ['http', 'https', 'file', 'data'], a: ['http', 'https', 'mailto', 'file'] } });
  } catch { return '<div class="readme-empty"><span>⌁</span><p>No Markdown README was found in this project.</p></div>'; }
}
async function getGitInfo(root) {
  try {
    const git = simpleGit(root);
    const [remotes, log, branch, firstCommit, shortlog, totalCommits, recentCommits] = await Promise.all([git.getRemotes(true), git.log({ maxCount: 1 }), git.branchLocal(), git.raw(['log', '--reverse', '--format=%aI', '-1']), git.raw(['shortlog', '-sne', '--all']), git.raw(['rev-list', '--count', 'HEAD']), git.raw(['rev-list', '--count', '--since=30 days ago', 'HEAD'])]);
    const remote = remotes[0]?.refs?.fetch || '';
    return { provider: providerFor(remote), remote, commits: Number(totalCommits.trim()) || 0, recentCommits: Number(recentCommits.trim()) || 0, branch: branch.current || 'HEAD', firstCommit: firstCommit.trim() || null, contributors: parseShortlog(shortlog), latest: log.latest ? { hash: log.latest.hash?.slice(0, 7), message: log.latest.message, date: log.latest.date } : null };
  } catch { return { provider: 'Local', remote: '', commits: 0, recentCommits: 0, branch: 'No branch', firstCommit: null, contributors: [], latest: null }; }
}

async function detectLicense(root) {
  try { const pkg = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8')); if (pkg.license) return { name: pkg.license, source: 'package.json' }; } catch { /* not a node project */ }
  for (const filename of ['LICENSE', 'LICENSE.md', 'LICENCE', 'LICENCE.md']) try {
    const text = await fs.readFile(path.join(root, filename), 'utf8');
    const spdx = await import('spdx-license-list/full.js').catch(() => null);
    const matched = spdx && Object.entries(spdx.default || spdx).find(([, value]) => value.licenseText && normaliseLicense(value.licenseText) === normaliseLicense(text));
    if (matched) return { name: matched[0], source: filename };
    const match = text.match(/MIT License|Apache License,? Version 2\.0|GNU GENERAL PUBLIC LICENSE|Mozilla Public License/i);
    return { name: match ? match[0].replace(/,? Version 2\.0/i, ' 2.0') : 'Custom license', source: filename };
  } catch { /* next */ }
  return { name: 'No license detected', source: '' };
}
function normaliseLicense(text) { return text.replace(/copyright\s*\(c\)?\s*\[?year\]?[^\n]*/ig, '').replace(/\s+/g, ' ').trim().toLowerCase(); }
function providerFor(remote) { if (/github\.com/i.test(remote)) return 'GitHub'; if (/gitlab\.com/i.test(remote)) return 'GitLab'; if (/bitbucket\.org/i.test(remote)) return 'Bitbucket'; return remote ? 'Other' : 'Local'; }
function projectSignals(files, license) { const names = files.map(file => file.relative.toLowerCase()); return { readme: names.some(name => /(?:^|\/)readme(?:\.(?:md|markdown|mdown|mkdn))?$/.test(name)), license: license.name !== 'No license detected', tests: names.some(name => /(?:^|\/)(?:test|tests|__tests__|spec)(?:\/|\.|$)/.test(name) || /(?:\.test|\.spec)\.[\w]+$/.test(name)), ci: names.some(name => /(?:^|\/)(?:\.github\/workflows|\.gitlab-ci\.yml|azure-pipelines\.yml|jenkinsfile)/.test(name)), manifest: names.some(name => /(?:^|\/)(?:package\.json|composer\.json|pom\.xml|build\.gradle(?:\.kts)?|requirements[^/]*\.txt|go\.mod|cargo\.toml)$/.test(name)) }; }
function parseShortlog(value) { return value.split(/\r?\n/).flatMap(line => { const match = line.trim().match(/^(\d+)\s+(.+?)\s+<([^>]+)>$/); if (!match) return []; const [, commits, name, email] = match; const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex'); return [{ commits: Number(commits), name, avatar: `https://www.gravatar.com/avatar/${hash}?d=identicon&s=96` }]; }).slice(0, 12); }
async function getGitHubContributors(remote) { const match = remote.match(/github\.com[/:]([^/]+)\/([^/#]+?)(?:\.git)?$/i); if (!match) return []; const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5000); try { const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(match[1])}/${encodeURIComponent(match[2])}/contributors?per_page=12`, { signal: controller.signal, headers: { accept: 'application/vnd.github+json' } }); if (!response.ok) return []; const contributors = await response.json(); return Array.isArray(contributors) ? contributors.map(item => ({ name: item.login, commits: item.contributions, avatar: item.avatar_url, profile: item.html_url })) : []; } catch { return []; } finally { clearTimeout(timer); } }
function languageFor(file) { return LANGUAGE_BY_EXTENSION[path.extname(file).slice(1).toLowerCase()]?.[0] || 'text'; }
function shikiLanguage(language) { return ({ JavaScript: 'javascript', TypeScript: 'typescript', Python: 'python', JSON: 'json', HTML: 'html', CSS: 'css', Markdown: 'markdown', Shell: 'shell' })[language] || 'text'; }
function localBin(name) { const extension = process.platform === 'win32' ? '.cmd' : ''; const target = path.join(app.getAppPath(), 'node_modules', '.bin', `${name}${extension}`); return fssync.existsSync(target) ? target : null; }
function run(command, args, options) { return new Promise((resolve, reject) => { const child = spawn(command, args, { ...options, shell: false, windowsHide: true }); let stdout = '', stderr = ''; child.stdout?.on('data', data => { stdout += data; }); child.stderr?.on('data', data => { stderr += data; }); child.on('error', error => reject(Object.assign(error, { stdout, stderr }))); child.on('close', code => code === 0 ? resolve({ stdout, stderr }) : reject(Object.assign(new Error(stderr || `${path.basename(command)} exited ${code}`), { stdout, stderr }))); }); }
async function runCodexCli(cwd, prompt, onProgress, retriedAfterUpdate = false) {
  const candidates = codexCliCandidates();
  const errors = [];
  for (const command of candidates) try {
    await runCodexCommand(command, ['exec', '--sandbox', 'workspace-write', '--skip-git-repo-check', prompt], cwd, onProgress, 'Codex finished successfully.');
    return;
  } catch (error) {
    const message = error.message || String(error);
    if (!retriedAfterUpdate && /requires a newer version of Codex/i.test(message)) {
      onProgress?.({ status: 'output', text: 'Codex needs an update for this model. Updating the local CLI, then retrying…' });
      try {
        await runCodexCommand(command, ['update'], cwd, onProgress, 'Codex CLI updated. Retrying the fix…');
      } catch (updateError) {
        if (!/Could not detect the Codex installation method/i.test(updateError.message || '')) throw updateError;
        onProgress?.({ status: 'output', text: 'The desktop-managed CLI cannot update itself. Downloading the latest official Codex CLI for this fix…' });
        return runLatestCodexCli(cwd, prompt, onProgress);
      }
      return runCodexCli(cwd, prompt, onProgress, true);
    }
    if (!/ENOENT|not recognized as an internal or external command/i.test(message)) throw new Error(`Codex CLI failed. ${message}`);
    errors.push(message);
  }
  throw new Error(`Unable to run the Codex CLI. Install the standalone Codex CLI or set CODEX_CLI_PATH. ${errors.join(' | ')}`.trim());
}
async function runLatestCodexCli(cwd, prompt, onProgress) {
  const npxScript = npxCliScript();
  if (!npxScript) throw new Error('Codex needs an update, but npm is unavailable to download the latest CLI. Update the Codex desktop app and try again.');
  const args = [npxScript, '--yes', '@openai/codex@latest', 'exec', '--sandbox', 'workspace-write', '--skip-git-repo-check', prompt];
  await runCodexCommand(process.execPath, args, cwd, onProgress, 'Codex finished successfully using the latest CLI.', { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
}
function runCodexCommand(command, args, cwd, onProgress, completedText, options = {}) {
  return new Promise((resolve, reject) => {
    const shell = process.platform === 'win32' && /\.cmd$/i.test(command);
    const child = spawn(command, args, { ...options, cwd, shell, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    onProgress?.({ status: 'started', text: `> ${path.basename(command)} ${args.slice(0, 4).join(' ')}` });
    child.stdout?.on('data', data => onProgress?.({ status: 'output', text: data.toString().slice(-4000) }));
    child.stderr?.on('data', data => { const text = data.toString(); stderr += text; onProgress?.({ status: 'output', text: text.slice(-4000) }); });
    child.on('error', error => reject(error));
    child.on('close', code => code === 0 ? (onProgress?.({ status: 'completed', text: completedText }), resolve()) : reject(new Error(stderr || `Codex exited with code ${code}.`)));
  });
}
function npxCliScript() {
  const nodeDirectories = [...new Set([path.dirname(process.execPath), ...(process.env.Path || process.env.PATH || '').split(path.delimiter).filter(Boolean)])];
  return nodeDirectories.map(directory => path.join(directory, 'node_modules', 'npm', 'bin', 'npx-cli.js')).find(candidate => fssync.existsSync(candidate));
}
function codexCliCandidates() {
  const pathEntries = (process.env.Path || process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const localAppData = process.env.LOCALAPPDATA || path.join(app.getPath('home'), 'AppData', 'Local');
  const knownLocations = process.platform === 'win32'
    ? [path.join(localAppData, 'OpenAI', 'Codex', 'bin', 'codex.exe'), ...pathEntries.flatMap(entry => [path.join(entry, 'codex.exe'), path.join(entry, 'codex.cmd')])]
    : pathEntries.map(entry => path.join(entry, 'codex'));
  return [...new Set([process.env.CODEX_CLI_PATH, ...knownLocations.filter(candidate => fssync.existsSync(candidate)), process.platform === 'win32' ? 'codex.cmd' : 'codex', 'codex'].filter(Boolean))];
}
function runNodeScript(script, args) { return run(process.execPath, [path.join(path.dirname(fileURLToPath(import.meta.url)), 'workers', script), ...args], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } }); }
function runNodeScriptStreaming(script, args, onLine) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(path.dirname(fileURLToPath(import.meta.url)), 'workers', script), ...args], { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' }, windowsHide: true });
    let buffer = ''; let stderr = ''; let chain = Promise.resolve();
    child.stdout.on('data', data => { buffer += data; const lines = buffer.split(/\r?\n/); buffer = lines.pop(); lines.filter(Boolean).forEach(line => { chain = chain.then(() => onLine(line)); }); });
    child.stderr.on('data', data => { stderr += data; });
    child.on('error', reject);
    child.on('close', async code => { if (buffer.trim()) chain = chain.then(() => onLine(buffer)); await chain; code === 0 ? resolve() : reject(new Error(stderr || `Worker exited ${code}`)); });
  });
}
async function runProjectWorker(script, project, args, onLine) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-files-'));
  const fileListPath = path.join(directory, 'files.json');
  try {
    await fs.writeFile(fileListPath, JSON.stringify(project.files.map(file => file.relative)), 'utf8');
    return await runNodeScriptStreaming(script, [project.path, fileListPath, ...args], onLine);
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}
function safeJson(value, fallback) { try { return JSON.parse(value); } catch { const start = value.indexOf('{'); const array = value.indexOf('['); const index = start < 0 ? array : array < 0 ? start : Math.min(start, array); try { return JSON.parse(value.slice(index)); } catch { return fallback; } } }
async function snippetAt(root, relative, line) { try { const source = await fs.readFile(path.join(root, relative), 'utf8'); return source.split(/\r?\n/).slice(Math.max(0, line - 3), line + 2).join('\n'); } catch { return ''; } }
async function redactedSnippetAt(root, relative, line) {
  try {
    const source = await fs.readFile(path.join(root, relative), 'utf8');
    const lines = source.split(/\r?\n/);
    const start = Math.max(0, line - 3);
    const end = line + 2;
    if (/-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/.test(lines[line - 1] || '')) return '[Sensitive private key redacted]';
    return lines.slice(start, end).map((entry, index) => start + index === line - 1 ? redactSecretLine(entry) : entry).join('\n');
  } catch { return ''; }
}
function redactSecretLine(line) {
  return line
    .replace(/((?:api[_-]?key|token|secret|password|private[_-]?key|credential)[\w.-]*\s*[:=]\s*)(['"]?)[^'"\s,}]+\2/ig, '$1[REDACTED]')
    .replace(/\b(?:sk-(?:proj-|svcacct-)?|gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AKIA|ASIA|AIza|npm_|SG\.)[A-Za-z0-9_./=-]+/g, '[REDACTED]');
}
function isPotentialSecretFile(relative) { return /(?:^|\/)(?:\.env(?:\..*)?|\.npmrc|\.pypirc|id_rsa|credentials(?:\.[\w-]+)?|secrets?(?:\.[\w-]+)?)$/i.test(relative); }
async function findJson(folder) { const names = await fs.readdir(folder, { recursive: true }); for (const name of names) if (String(name).endsWith('.json')) return safeJson(await fs.readFile(path.join(folder, name), 'utf8'), null); return null; }
function normaliseKnip(json, project, make) {
  if (!json) return []; const issues = [];
  const add = (items, reason, defaultFile = '') => (items || []).forEach(item => { const file = typeof item === 'string' ? item : item.file || defaultFile || item.name || ''; if (file) issues.push(make({ file, line: item.line || 1, symbol: typeof item === 'string' ? '' : item.name || '', reason })); });
  add(json.files, 'Unused file reported by Knip.'); add(json.exports, 'Unused export reported by Knip.'); add(json.dependencies, 'Unused dependency reported by Knip.');
  for (const group of json.issues || []) { add(group.dependencies, 'Unused dependency reported by Knip.', group.file); add(group.exports, 'Unused export reported by Knip.', group.file); add(group.types, 'Unused type export reported by Knip.', group.file); }
  return issues;
}
function parseSlopOutput(stdout) {
  const parsed = safeJson(stdout, []); const values = Array.isArray(parsed) ? parsed : parsed.issues || parsed.packages || parsed.findings || [];
  return values.map(item => ({ file: item.file || item.path || item.locations?.[0]?.path || 'package.json', line: item.line || item.locations?.[0]?.line || 1, symbol: item.name || item.package || item.ruleId || '', reason: item.reason || item.message || `Suspicious package ${item.name || item.package || ''}.` }));
}
