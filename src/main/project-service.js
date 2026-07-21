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
const SCAN_VERSION = 13;
const AWARD_SOURCE_FILE = /\.(?:[cm]?js|jsx|tsx?|mjs|cjs|java|php|py|rb|go|rs|cs|swift|kt)$/i;
const MAX_AWARD_FILE_BYTES = 2 * 1024 * 1024;
const MAX_CONCURRENT_CHECKS = 4;
const PRETTIER_EXTENSIONS = new Set(['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'json', 'css', 'scss', 'less', 'html', 'vue', 'yaml', 'yml']);
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
  { id: 'formatting-drift', label: 'Formatting Drift', command: 'prettier', group: 'Foundations' },
  { id: 'debug-code', label: 'Debug Code', command: 'built-in', group: 'Foundations' },
  { id: 'todo-debt', label: 'TODO Debt', command: 'built-in', group: 'Foundations' },
  { id: 'dead-code', label: 'Dead Code', command: 'knip', group: 'Clean code' },
  { id: 'duplicate-code', label: 'Duplicate Code', command: 'jscpd', group: 'Clean code' },
  { id: 'duplicate-imports', label: 'Duplicate Imports', command: 'built-in', group: 'Clean code' },
  { id: 'empty-functions', label: 'Empty Functions', command: 'built-in', group: 'Clean code' },
  { id: 'magic-values', label: 'Magic Values', command: 'built-in', group: 'Clean code' },
  { id: 'empty-artifacts', label: 'Empty Files & Folders', command: 'built-in', group: 'Project cleanup' },
  { id: 'long-functions', label: 'Long Functions', command: 'built-in', group: 'Maintainability' },
  { id: 'large-files', label: 'Large Source Files', command: 'built-in', group: 'Maintainability' },
  { id: 'parameter-bloat', label: 'Parameter Bloat', command: 'built-in', group: 'Maintainability' },
  { id: 'nested-ternaries', label: 'Nested Ternaries', command: 'built-in', group: 'Maintainability' },
  { id: 'complex-logic', label: 'Complex Logic', command: 'built-in', group: 'Maintainability' },
  { id: 'logic-conditions', label: 'Logic Conditions', command: 'built-in', group: 'Reliability' },
  { id: 'non-strict-equality', label: 'Non-strict Equality', command: 'built-in', group: 'Reliability' },
  { id: 'missing-switch-default', label: 'Missing Switch Default', command: 'built-in', group: 'Reliability' },
  { id: 'error-handling', label: 'Error Handling', command: 'built-in', group: 'Reliability' },
  { id: 'empty-branches', label: 'Empty Branches', command: 'built-in', group: 'Reliability' },
  { id: 'broad-exception-handling', label: 'Broad Exceptions', command: 'built-in', group: 'Reliability' },
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
  { id: 'insecure-http', label: 'Insecure HTTP', command: 'built-in', group: 'Security' },
  { id: 'sensitive-logging', label: 'Sensitive Logging', command: 'built-in', group: 'Security' },
  { id: 'command-injection', label: 'Command Injection', command: 'built-in', group: 'Security' },
  { id: 'permissive-cors', label: 'Permissive CORS', command: 'built-in', group: 'Security' },
  { id: 'prototype-pollution', label: 'Prototype Pollution', command: 'built-in', group: 'Security' },
  { id: 'unsafe-file-uploads', label: 'Unsafe File Uploads', command: 'built-in', group: 'Security' },
  { id: 'insecure-defaults', label: 'Insecure Defaults', command: 'built-in', group: 'Security' },
  { id: 'predictable-identifiers', label: 'Predictable Identifiers', command: 'built-in', group: 'Security' },
  { id: 'unsafe-operations', label: 'Unsafe Operations', command: 'built-in', group: 'Runtime safety' },
  { id: 'unbounded-loops', label: 'Unbounded Loops', command: 'built-in', group: 'Runtime safety' },
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
      'duplicate-imports': () => this.runCodeQuality(project, 'duplicate-imports'),
      'empty-functions': () => this.runCodeQuality(project, 'empty-functions'),
      whitespace: () => this.runWhitespace(project),
      'formatting-drift': () => this.runFormattingDrift(project),
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
      'non-strict-equality': () => this.runCodeQuality(project, 'non-strict-equality'),
      'missing-switch-default': () => this.runCodeQuality(project, 'missing-switch-default'),
      'error-handling': () => this.runCodeQuality(project, 'error-handling'),
      'empty-branches': () => this.runCodeQuality(project, 'empty-branches'),
      'broad-exception-handling': () => this.runCodeQuality(project, 'broad-exception-handling'),
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
      'insecure-http': () => this.runCodeQuality(project, 'insecure-http'),
      'sensitive-logging': () => this.runCodeQuality(project, 'sensitive-logging'),
      'command-injection': () => this.runCodeQuality(project, 'command-injection'),
      'permissive-cors': () => this.runCodeQuality(project, 'permissive-cors'),
      'prototype-pollution': () => this.runCodeQuality(project, 'prototype-pollution'),
      'unsafe-file-uploads': () => this.runCodeQuality(project, 'unsafe-file-uploads'),
      'insecure-defaults': () => this.runCodeQuality(project, 'insecure-defaults'),
      'predictable-identifiers': () => this.runCodeQuality(project, 'predictable-identifiers'),
      'unsafe-operations': () => this.runCodeQuality(project, 'unsafe-operations'),
      'unbounded-loops': () => this.runCodeQuality(project, 'unbounded-loops'),
      'package-integrity': () => this.runPackageIntegrity(project),
      'deprecated-apis': () => this.runCodeQuality(project, 'deprecated-apis'),
      'unsafe-external-links': () => this.runCodeQuality(project, 'unsafe-external-links'),
      'image-alt-text': () => this.runCodeQuality(project, 'image-alt-text')
    };
    let scanHadErrors = false;
    const activeChecks = CHECKS.filter(check => !project.disabledChecks.includes(check.id));
    const resultPairs = await mapWithConcurrency(activeChecks, MAX_CONCURRENT_CHECKS, async check => {
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
    });
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
  async getMergeGate(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before using Redox Gate.');
    const git = simpleGit(project.path);
    let status;
    try { status = await git.status(); }
    catch { return { available: false, reason: 'Redox Gate needs a Git working tree to inspect the current change set.' }; }

    const [unstaged, staged] = await Promise.all([
      git.raw(['diff', '--numstat']).catch(() => ''),
      git.raw(['diff', '--cached', '--numstat']).catch(() => '')
    ]);
    const changed = new Map();
    const collectNumstat = raw => raw.split(/\r?\n/).filter(Boolean).forEach(line => {
      const [added, deleted, file] = line.split('\t');
      if (!file) return;
      const current = changed.get(file) || { file, additions: 0, deletions: 0, untracked: false };
      current.additions += Number(added) || 0;
      current.deletions += Number(deleted) || 0;
      changed.set(file, current);
    });
    collectNumstat(unstaged);
    collectNumstat(staged);
    [...new Set([...(status.not_added || []), ...(status.created || [])])].forEach(file => {
      const current = changed.get(file) || { file, additions: 0, deletions: 0, untracked: true };
      current.untracked = true;
      changed.set(file, current);
    });
    [...new Set([...(status.modified || []), ...(status.staged || []), ...(status.deleted || []), ...(status.renamed || []).flatMap(item => [item.from, item.to]).filter(Boolean)])].forEach(file => {
      if (!changed.has(file)) changed.set(file, { file, additions: 0, deletions: 0, untracked: false });
    });

    const changedFiles = [...changed.values()].sort((left, right) => right.additions + right.deletions - (left.additions + left.deletions) || left.file.localeCompare(right.file));
    const issues = Object.values(project.cached?.results || {}).flat();
    const issueWeight = issue => gateRiskWeight(issue.type);
    const relatedFindings = issues.filter(issue => changed.has(issue.file)).map(issue => ({
      id: issue.id, file: issue.file, line: issue.line, endLine: issue.endLine, type: issue.type,
      reason: issue.reason, weight: issueWeight(issue), blocking: issueWeight(issue) >= 10
    })).sort((left, right) => right.weight - left.weight || left.file.localeCompare(right.file));
    const blockingFindings = relatedFindings.filter(issue => issue.blocking);
    const highRiskSurfaces = changedFiles.filter(item => /(?:^|[\\/_-])(?:auth|login|session|token|identity|credential|payment|billing|crypto|security|admin)(?:[\\/_-]|$)/i.test(item.file) || /(?:^|\/)(?:package(?:-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock|cargo\.lock)$/i.test(item.file)).map(item => item.file);
    const testCommands = await mergeGateCommands(project.path);
    const changedLineCount = changedFiles.reduce((total, item) => total + item.additions + item.deletions, 0);
    let statusName = 'CLEAR';
    let title = 'Clear for human review';
    let summary = 'The changed files have no high-risk scan signals. Review the diff and run the listed verification before merging.';
    const reasons = [];
    if (!changedFiles.length) {
      statusName = 'AWAITING';
      title = 'Awaiting a change set';
      summary = 'There is no staged, unstaged, or untracked change for Redox Gate to evaluate yet.';
      reasons.push('Make or stage a focused change, then refresh the gate.');
    } else if (blockingFindings.length) {
      statusName = 'HOLD';
      title = 'Hold: high-risk evidence touches this diff';
      summary = 'At least one changed file also has a high-risk static signal. Resolve or explicitly review that evidence before merge.';
      reasons.push(`${blockingFindings.length} high-risk scan signal${blockingFindings.length === 1 ? '' : 's'} intersects the current diff.`);
    } else if (relatedFindings.length || highRiskSurfaces.length || changedFiles.length > 8) {
      statusName = 'REVIEW';
      title = 'Review before merge';
      summary = 'The diff intersects active scan evidence, a sensitive surface, or a broad change set. Keep review deliberate.';
      if (relatedFindings.length) reasons.push(`${relatedFindings.length} active scan signal${relatedFindings.length === 1 ? '' : 's'} intersects changed files.`);
      if (highRiskSurfaces.length) reasons.push(`${highRiskSurfaces.length} sensitive or dependency surface${highRiskSurfaces.length === 1 ? '' : 's'} changed.`);
      if (changedFiles.length > 8) reasons.push(`${changedFiles.length} files changed; split the work if it is not one cohesive review.`);
    } else {
      reasons.push('No high-risk static signal intersects the current diff.');
      if (changedLineCount) reasons.push(`${changedLineCount} changed line${changedLineCount === 1 ? '' : 's'} are visible in the working tree.`);
    }
    return {
      available: true, status: statusName, title, summary, reasons, changedFiles, changedLineCount,
      relatedFindings: relatedFindings.slice(0, 12), blockingFindings: blockingFindings.length,
      highRiskSurfaces: highRiskSurfaces.slice(0, 8), testCommands,
      branch: status.current || project.metadata.git.branch || 'Unknown branch',
      hasStaged: Boolean((status.staged || []).length), generatedAt: new Date().toISOString()
    };
  }
  async getAwards(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before viewing awards.');
    const cacheKey = project.cached?.lastScan || `${project.metadata.fileCount}:${project.metadata.size}`;
    if (project.awards?.cacheKey === cacheKey) return project.awards.data;
    const sourceFiles = project.files.filter(file => AWARD_SOURCE_FILE.test(file.relative));
    const scanned = await mapWithConcurrency(sourceFiles, 8, async file => {
      try {
        const stat = await fs.stat(file.full);
        if (stat.size > MAX_AWARD_FILE_BYTES) return null;
        const lines = (await fs.readFile(file.full, 'utf8')).split(/\r?\n/);
        return { file: file.relative, language: languageFor(file.relative), lines, lineCount: lines.length, commentLines: lines.filter(line => /^\s*(?:\/\/|#|\/\*|\*|\*\/)/.test(line)).length };
      } catch { return null; }
    });
    const codeFiles = scanned.filter(Boolean);
    const structures = codeFiles.flatMap(file => awardStructures(file));
    const longestFile = [...codeFiles].sort((left, right) => right.lineCount - left.lineCount)[0];
    const longestFunction = structures.filter(item => item.kind === 'function').sort((left, right) => right.lines - left.lines)[0];
    const longestClass = structures.filter(item => item.kind === 'class').sort((left, right) => right.lines - left.lines)[0];
    const widestFunction = structures.filter(item => item.kind === 'function' && item.parameters > 0).sort((left, right) => right.parameters - left.parameters || right.lines - left.lines)[0];
    const mostComments = [...codeFiles].filter(file => file.commentLines > 0).sort((left, right) => right.commentLines - left.commentLines)[0];
    const issues = Object.values(project.cached?.results || {}).flat();
    const issuesByFile = new Map();
    issues.forEach(issue => issuesByFile.set(issue.file, (issuesByFile.get(issue.file) || 0) + 1));
    const findingHotspot = [...issuesByFile.entries()].sort((left, right) => right[1] - left[1])[0];
    const duplicateFiles = new Map();
    issues.filter(issue => issue.type === 'duplicate-code').forEach(issue => duplicateFiles.set(issue.file, (duplicateFiles.get(issue.file) || 0) + 1));
    const duplicateHotspot = [...duplicateFiles.entries()].sort((left, right) => right[1] - left[1])[0];
    const todoHotspot = findingHotspotFor(issues, 'todo-debt');
    const debugHotspot = findingHotspotFor(issues, 'debug-code');
    const largestOnDisk = project.metadata.largestFiles?.[0];
    const busiestArea = project.metadata.topLevel?.[0];
    const awards = [
      longestFile && { id: 'longest-file', title: 'Longest file', value: longestFile.lineCount.toLocaleString(), unit: 'lines', file: longestFile.file, line: 1, endLine: longestFile.lineCount, language: longestFile.language, description: 'The source file with the most lines.' },
      largestOnDisk && { id: 'largest-on-disk', title: 'Largest file on disk', value: formatAwardBytes(largestOnDisk.size), unit: '', file: largestOnDisk.path, language: languageFor(largestOnDisk.path), description: 'The largest tracked project file by size.' },
      longestFunction && { id: 'longest-function', title: 'Longest function', value: longestFunction.lines.toLocaleString(), unit: 'lines', file: longestFunction.file, line: longestFunction.start, endLine: longestFunction.end, language: longestFunction.language, symbol: longestFunction.name, description: 'The longest detected function body in the project.' },
      longestClass && { id: 'longest-class', title: 'Longest class', value: longestClass.lines.toLocaleString(), unit: 'lines', file: longestClass.file, line: longestClass.start, endLine: longestClass.end, language: longestClass.language, symbol: longestClass.name, description: 'The longest detected class body in the project.' },
      widestFunction && { id: 'widest-signature', title: 'Widest function signature', value: widestFunction.parameters.toLocaleString(), unit: 'parameters', file: widestFunction.file, line: widestFunction.start, endLine: widestFunction.end, language: widestFunction.language, symbol: widestFunction.name, description: 'The detected function accepting the most parameters.' },
      mostComments && { id: 'comment-heavy-file', title: 'Most comment-heavy file', value: mostComments.commentLines.toLocaleString(), unit: 'comment lines', file: mostComments.file, language: mostComments.language, description: 'The source file with the most standalone comment lines.' },
      busiestArea && { id: 'busiest-area', title: 'Busiest project area', value: busiestArea.count.toLocaleString(), unit: 'files', file: busiestArea.name, language: 'Project structure', description: 'The top-level project area containing the most files.' },
      findingHotspot && { id: 'finding-hotspot', title: 'Finding hotspot', value: findingHotspot[1].toLocaleString(), unit: 'findings', file: findingHotspot[0], language: languageFor(findingHotspot[0]), description: 'The file with the most active Code Redox findings.' },
      duplicateHotspot && { id: 'duplicate-hotspot', title: 'Duplicate magnet', value: duplicateHotspot[1].toLocaleString(), unit: 'duplicate blocks', file: duplicateHotspot[0], language: languageFor(duplicateHotspot[0]), description: 'The file involved in the most duplicate-code findings.' },
      todoHotspot && { id: 'todo-hotspot', title: 'TODO collector', value: todoHotspot[1].toLocaleString(), unit: 'TODO notes', file: todoHotspot[0], language: languageFor(todoHotspot[0]), description: 'The file containing the most current TODO, FIXME, HACK, or XXX notes.' },
      debugHotspot && { id: 'debug-hotspot', title: 'Debug-code holdout', value: debugHotspot[1].toLocaleString(), unit: 'debug calls', file: debugHotspot[0], language: languageFor(debugHotspot[0]), description: 'The file with the most active console or debugger findings.' }
    ].filter(Boolean);
    const data = { awards, scannedFiles: codeFiles.length, skippedLargeFiles: sourceFiles.length - codeFiles.length, maxFileBytes: MAX_AWARD_FILE_BYTES };
    project.awards = { cacheKey, data };
    return data;
  }
  async getTimeMachine(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before viewing its history.');
    const cacheKey = project.cached?.lastScan || 'unscanned';
    if (project.timeMachine?.cacheKey === cacheKey) return project.timeMachine.data;
    const git = simpleGit(project.path);
    let commits;
    try { commits = (await git.log({ maxCount: 36 })).all; }
    catch { return { available: false, reason: 'Git history is unavailable for this project.' }; }
    if (!commits.length) return { available: false, reason: 'This project has no commits to replay yet.' };
    const issues = Object.values(project.cached?.results || {}).flat();
    const packages = await discoverPackages(project.path, project.files).catch(() => []);
    const unusedPackages = packages.filter(item => item.usage === 'unused').length;
    const trackedIssues = [...issues].sort((left, right) => timeMachinePriority(right) - timeMachinePriority(left)).slice(0, 240);
    const lineCommits = await mapWithConcurrency(trackedIssues, 6, async issue => {
      try {
        const blame = await git.raw(['blame', '--line-porcelain', '-L', `${issue.line},${issue.line}`, '--', issue.file]);
        const hash = blame.match(/^([0-9a-f]{40})\s/m)?.[1];
        return hash ? { issue, hash } : null;
      } catch { return null; }
    });
    const linkedByCommit = new Map();
    lineCommits.filter(Boolean).forEach(({ issue, hash }) => {
      const items = linkedByCommit.get(hash) || [];
      items.push(issue);
      linkedByCommit.set(hash, items);
    });
    const timeline = commits.map((commit, index) => {
      const linked = linkedByCommit.get(commit.hash) || [];
      return { hash: commit.hash, shortHash: commit.hash.slice(0, 7), date: commit.date, subject: commit.message || 'Commit', number: Math.max(1, (project.metadata.git.commits || commits.length) - index), findings: linked.slice(0, 3).map(issue => ({ id: issue.id, type: issue.type, reason: issue.reason, file: issue.file, line: issue.line })), findingCount: linked.length };
    }).filter(commit => commit.findingCount).slice(0, 14).reverse();
    const count = type => issues.filter(issue => issue.type === type).length;
    const runtimeRisk = ['deprecated-apis', 'unsafe-operations', 'logic-conditions', 'error-handling'].reduce((total, type) => total + count(type), 0);
    const pulse = [
      { label: 'Dead code', count: count('dead-code') },
      { label: 'Duplicate logic', count: count('duplicate-code') },
      { label: 'API & runtime risk', count: runtimeRisk },
      { label: 'Dependency bloat', count: count('package-integrity') + unusedPackages }
    ].map(item => ({ ...item, level: Math.min(100, Math.round(Math.log2(item.count + 1) * 20)) }));
    const duplicates = count('duplicate-code');
    const deadCode = count('dead-code');
    const emptyArtifacts = count('empty-artifacts');
    const estimatedLines = deadCode * 12 + duplicates * 10 + emptyArtifacts + unusedPackages * 2;
    const data = {
      available: true,
      totalCommits: project.metadata.git.commits || commits.length,
      sampledFindings: trackedIssues.length,
      findings: issues.length,
      pulse,
      timeline,
      restoration: {
        deleteArtifacts: emptyArtifacts,
        removePackages: unusedPackages,
        mergeDuplicates: duplicates,
        updateImports: deadCode,
        estimatedLines,
        complexityReduction: Math.min(55, duplicates * 3 + deadCode),
        maintainabilityGain: Math.min(35, Math.ceil((duplicates + deadCode + unusedPackages) / 2))
      }
    };
    project.timeMachine = { cacheKey, data };
    return data;
  }
  async getEvolutionForecast(projectId) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before viewing its forecast.');
    const cacheKey = project.cached?.lastScan || 'unscanned';
    if (project.evolutionForecast?.cacheKey === cacheKey) return project.evolutionForecast.data;
    const issues = Object.values(project.cached?.results || {}).flat();
    const packages = await discoverPackages(project.path, project.files).catch(() => []);
    let fileChanges = new Map();
    let commitsAnalyzed = 0;
    try {
      const history = await simpleGit(project.path).raw(['log', '--max-count=60', '--format=__CRX_COMMIT__%H', '--name-only', '--']);
      ({ fileChanges, commitsAnalyzed } = recentFileChangeStats(history));
    } catch { /* A forecast can still use scan evidence when Git history is not available. */ }
    const issuesByFile = new Map();
    issues.forEach(issue => { const values = issuesByFile.get(issue.file) || []; values.push(issue); issuesByFile.set(issue.file, values); });
    const forecasts = [];
    const complexityChecks = new Set(['long-functions', 'complex-logic', 'nested-ternaries', 'parameter-bloat']);
    const reliabilityChecks = new Set(['logic-conditions', 'error-handling', 'unsafe-operations', 'deprecated-apis']);
    const securityChecks = new Set(['secrets', 'weak-cryptography', 'insecure-randomness', 'unvalidated-redirects', 'sql-injection', 'path-traversal', 'xss-sinks', 'tls-validation', 'unsafe-deserialization', 'regex-dos', 'insecure-cookies']);
    for (const [file, fileIssues] of issuesByFile) {
      const changes = fileChanges.get(file)?.size || 0;
      const categories = new Set(fileIssues.map(issue => issue.type));
      const complexity = fileIssues.filter(issue => complexityChecks.has(issue.type)).length;
      const risk = fileIssues.filter(issue => reliabilityChecks.has(issue.type) || securityChecks.has(issue.type)).length;
      const authSurface = /(?:^|[\\/_-])(?:auth|login|session|token|identity|credential)[\\/_-]|(?:auth|login|session|token|identity|credential)/i.test(file);
      if (authSurface && changes >= 2 && risk >= 2) {
        forecasts.push(makeForecast({
          id: `auth:${file}`, kind: 'Authentication regression risk', confidence: changes >= 4 || risk >= 4 ? 'High' : 'Moderate', priority: 96,
          file, evidence: [`Changed in ${changes} of the last ${commitsAnalyzed || 60} commits`, `${risk} active security or reliability findings`, 'Path is part of the authentication surface'],
          prediction: `${file} is a change-heavy authentication surface with active validation or reliability signals. Further feature work is likely to increase regression risk until its responsibilities are reduced.`,
          action: 'Review the linked findings, isolate validation and token/session handling, then add focused tests before extending this module.'
        }));
        continue;
      }
      if (changes >= 3 && complexity >= 2) {
        forecasts.push(makeForecast({
          id: `complexity:${file}`, kind: 'Feature-delivery bottleneck', confidence: changes >= 5 || complexity >= 4 ? 'High' : 'Moderate', priority: 82,
          file, evidence: [`Changed in ${changes} recent commits`, `${complexity} active complexity findings`, `${categories.size} active audit categories in the same file`],
          prediction: `${file} is both frequently edited and structurally complex. If the current change pattern continues, future features are likely to take longer and carry more review risk here.`,
          action: 'Split a cohesive responsibility out of this file before adding the next feature, then cover the seam with tests.'
        }));
        continue;
      }
      if (changes >= 4 && fileIssues.length >= 4 && categories.size >= 3) {
        forecasts.push(makeForecast({
          id: `hotspot:${file}`, kind: 'Change-concentration hotspot', confidence: 'High', priority: 72,
          file, evidence: [`Changed in ${changes} recent commits`, `${fileIssues.length} active findings`, `${categories.size} independent audit categories`],
          prediction: `${file} is accumulating both change frequency and diverse quality signals. It is likely to become a maintenance hotspot unless the next change reduces, rather than adds to, its responsibilities.`,
          action: 'Use the linked findings to define a small refactor boundary and keep the next feature outside that boundary where possible.'
        }));
      }
    }
    const duplicates = issues.filter(issue => issue.type === 'duplicate-code');
    const duplicateFiles = new Set(duplicates.map(issue => issue.file));
    if (duplicates.length >= 2 && duplicateFiles.size >= 2) forecasts.push(makeForecast({
      id: 'duplicate-logic', kind: 'Repeated utility drift', confidence: duplicates.length >= 5 ? 'High' : 'Moderate', priority: 78,
      evidence: [`${duplicates.length} duplicate-code findings`, `Spans ${duplicateFiles.size} files`, 'The scanner found repeated implementation patterns'],
      prediction: `Repeated implementations already span ${duplicateFiles.size} files. New features are likely to add another variant and increase maintenance overhead until the shared behavior is consolidated.`,
      action: 'Choose one canonical implementation, migrate callers incrementally, and add a small contract test around it.'
    }));
    const unusedPackages = packages.filter(item => item.usage === 'unused').length;
    const packageSignals = issues.filter(issue => issue.type === 'package-integrity').length;
    if (packages.length >= 12 && (unusedPackages >= 3 || packageSignals >= 3)) forecasts.push(makeForecast({
      id: 'dependency-footprint', kind: 'Dependency maintenance drag', confidence: unusedPackages >= 5 || packageSignals >= 5 ? 'High' : 'Moderate', priority: 65,
      evidence: [`${packages.length} declared packages`, `${unusedPackages} packages appear unused`, `${packageSignals} package-integrity findings`],
      prediction: `The dependency footprint has unused or suspicious entries. If it grows at the current rate, upgrades, audits, and install time are likely to become progressively more expensive.`,
      action: 'Remove confirmed unused packages first, then require every new dependency to have a direct import and an owner.'
    }));
    const runtimeSignals = issues.filter(issue => reliabilityChecks.has(issue.type)).length;
    if (runtimeSignals >= 5 && !forecasts.some(item => item.kind === 'Authentication regression risk')) forecasts.push(makeForecast({
      id: 'runtime-contracts', kind: 'Runtime contract fragility', confidence: runtimeSignals >= 9 ? 'High' : 'Moderate', priority: 60,
      evidence: [`${runtimeSignals} active reliability or runtime findings`, `${new Set(issues.filter(issue => reliabilityChecks.has(issue.type)).map(issue => issue.type)).size} separate reliability checks triggered`],
      prediction: `Several independent runtime-safety checks are active. Adding integrations or feature branches before these contracts are clarified is likely to raise the chance of behavior regressions.`,
      action: 'Turn the highest-risk conditions into explicit guards and add tests for invalid input and failure paths.'
    }));
    const data = {
      available: true,
      commitsAnalyzed,
      findingsAnalyzed: issues.length,
      packagesAnalyzed: packages.length,
      forecasts: forecasts.sort((left, right) => right.priority - left.priority).slice(0, 5)
    };
    project.evolutionForecast = { cacheKey, data };
    return data;
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
  async fixViaCodex(projectId, issueId, useFlightPlan = false) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.projectId !== projectId) throw new Error('That finding is no longer available.');
    const taskFile = `.coderedox-codex-task-${crypto.randomUUID()}.md`;
    const taskPath = path.join(project.path, taskFile);
    const flightPlan = useFlightPlan ? await this.getRepairFlightPlan(projectId, issueId) : null;
    const baseline = useFlightPlan ? await captureRepairBaseline(project.path) : null;
    const task = `# CodeRedox single-finding fix task\n\nFix only the finding below. Work only on files required by it, preserve project conventions, do not change unrelated code, do not commit or reset repository history, and verify the fix before finishing.${flightPlan ? `\n\n## Approved Repair Flight Plan\n${flightPlan.codexTask}` : ''}\n\n## Finding\n${buildPrompt(issue)}`;
    await fs.writeFile(taskPath, task, { encoding: 'utf8', flag: 'wx' });
    try {
      await runCodexCli(project.path, `Read ${taskFile} in the current project and complete the requested fix. Do not change unrelated code.`, event => this.send('codex:progress', { projectId, ...event }));
    } finally {
      await fs.unlink(taskPath).catch(() => {});
    }
    project.cached = null;
    return { message: 'Codex completed the requested fix.', receipt: flightPlan ? await buildRepairReceipt(project.path, flightPlan, baseline) : null };
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
  async getRepairFlightPlan(projectId, issueId) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.projectId !== projectId) throw new Error('That finding is no longer available.');

    const check = CHECKS.find(item => item.id === issue.type);
    const [relatedFiles, gitHistory, commands] = await Promise.all([
      findRepairRelatedFiles(project, issue),
      getRepairGitHistory(project.path, issue.file),
      getRepairVerificationCommands(project.path)
    ]);
    const group = check?.group || 'Code health';
    const impact = repairImpact(issue, group, relatedFiles.length, gitHistory.commits);
    const contract = repairContract(issue, group);
    return {
      issueId: issue.id,
      title: check?.label || issue.type,
      impact,
      target: { file: issue.file, line: issue.line, endLine: issue.endLine, symbol: issue.symbol || null },
      summary: `${issue.reason} This preflight is generated locally before any AI write is authorized.`,
      contract,
      scope: {
        allow: [issue.file, ...relatedFiles].slice(0, 6),
        avoid: ['Generated output, lockfiles, dependency manifests, and unrelated formatting unless the repair makes one necessary.'],
        relatedFiles
      },
      history: gitHistory,
      verification: {
        commands,
        scan: `Re-run ${check?.label || 'the selected'} check and review the resulting diff.`,
        rollback: 'Keep the repair in a separate commit or use your Git diff to revert the focused change.'
      },
      gates: [
        'Confirm this static signal matches the intended behavior before editing.',
        `Keep Codex inside the declared file scope (${[issue.file, ...relatedFiles].slice(0, 3).join(', ')}).`,
        'Review the diff, run the suggested verification, then let Code Redox re-scan the finding.'
      ],
      codexTask: `Repair Flight Plan for ${issue.file}:${issue.line}\n\nBehavior contract: ${contract}\n\nAllowed scope: ${[issue.file, ...relatedFiles].slice(0, 6).join(', ')}\n\nDo not modify generated output, lockfiles, dependency manifests, or unrelated formatting. Verify with: ${commands.join(' && ') || 'the nearest relevant test'}\n\nFinding:\n${buildPrompt(issue)}`
    };
  }
  async chatWithCodex(projectId, { message, mode = 'ask', history = [] } = {}) {
    const project = this.projects.get(projectId);
    if (!project) throw new Error('Open the project before starting a Codex chat.');
    const request = String(message || '').trim();
    if (!request) throw new Error('Enter a message for Codex.');
    if (!['ask', 'work'].includes(mode)) throw new Error('Unknown Codex chat mode.');
    const context = history.slice(-8).map(entry => `${entry.role === 'user' ? 'User' : 'Codex'}: ${String(entry.content || '').slice(0, 3500)}`).join('\n\n');
    const instructions = mode === 'work'
      ? 'The user explicitly authorized you to work in this repository. Make only the changes needed for the request, preserve project conventions, and explain what you changed and how you verified it.'
      : 'Answer as a repository guide. Do not modify files, run package managers, or make any external changes. Base your answer on the current project.';
    const taskFile = `.coderedox-codex-chat-${crypto.randomUUID()}.md`;
    const taskPath = path.join(project.path, taskFile);
    const task = `# Code Redox repository chat\n\nYou are Code Redox's repository assistant. ${instructions}\n\nProject root: ${project.path}\n\n${context ? `Recent conversation:\n${context}\n\n` : ''}Current user request:\n${request}\n\nRespond directly to the user with a concise, useful answer.`;
    await fs.writeFile(taskPath, task, { encoding: 'utf8', flag: 'wx' });
    let result;
    try {
      result = await runCodexCli(project.path, `Read ${taskFile} in the current project and follow its instructions.`, event => this.send('codex:chat-progress', { projectId, ...event }), false, { sandbox: mode === 'work' ? 'workspace-write' : 'read-only' });
    } finally {
      await fs.unlink(taskPath).catch(() => {});
    }
    if (mode === 'work') project.cached = null;
    const response = String(result?.stdout || '').trim();
    return { response: response || (mode === 'work' ? 'Codex completed the requested repository task.' : 'Codex completed the repository analysis.'), changedProject: mode === 'work' };
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
  async runFormattingDrift(project) {
    const candidates = project.files.filter(file => PRETTIER_EXTENSIONS.has(file.extension));
    const findings = await mapWithConcurrency(candidates, 6, async file => {
      const formatted = await prettierFormatFile(file);
      if (!formatted?.changed) return null;
      const line = firstChangedLine(formatted.source, formatted.output);
      return this.issue(project, 'formatting-drift', {
        file: file.relative,
        line,
        reason: 'Prettier would reformat this file. Restoring consistent structure makes follow-up AI edits easier to review safely.',
        symbol: 'Prettier format drift',
        snippet: await snippetAt(project.path, file.relative, line)
      });
    });
    return findings.filter(Boolean);
  }
  async formatWithPrettier(projectId, issueId) {
    const project = this.projects.get(projectId);
    const issue = this.issues.get(issueId);
    if (!project || !issue || issue.projectId !== projectId || issue.type !== 'formatting-drift') throw new Error('That formatting finding is no longer available.');
    const file = project.files.find(candidate => candidate.relative === issue.file);
    if (!file) throw new Error('The formatting target is no longer available.');
    const formatted = await prettierFormatFile(file);
    if (!formatted) throw new Error('Prettier could not parse this file with the available configuration.');
    if (formatted.changed) await fs.writeFile(file.full, formatted.output, 'utf8');
    project.cached = null;
    return { changed: formatted.changed, file: issue.file, message: formatted.changed ? `Formatted ${issue.file} with Prettier.` : `${issue.file} already matches Prettier.` };
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

const REPAIR_SEVERITY = {
  secrets: 5, 'sql-injection': 5, 'xss-sinks': 5, 'command-injection': 5, 'path-traversal': 5,
  'unsafe-file-uploads': 5, 'tls-validation': 5, 'unsafe-deserialization': 5, 'weak-cryptography': 4,
  'insecure-randomness': 4, 'permissive-cors': 4, 'logic-conditions': 4, 'error-handling': 4,
  'unsafe-operations': 4, 'duplicate-code': 3, 'complex-logic': 3, 'long-functions': 3
};

function repairImpact(issue, group, relatedCount, commitCount) {
  const score = (REPAIR_SEVERITY[issue.type] || (group === 'Security' ? 4 : 2)) + (relatedCount > 2 ? 1 : 0) + (commitCount > 6 ? 1 : 0);
  const level = score >= 5 ? 'High' : score >= 3 ? 'Guarded' : 'Focused';
  return {
    level,
    score: Math.min(10, score),
    explanation: `${group} signal${relatedCount ? ` with ${relatedCount} nearby reference${relatedCount === 1 ? '' : 's'}` : ''}${commitCount ? ` and ${commitCount} file commit${commitCount === 1 ? '' : 's'} in recent history` : ''}.`
  };
}

function repairContract(issue, group) {
  const contracts = {
    Security: 'Close the unsafe path while preserving legitimate, validated input and the current user-facing response.',
    Reliability: 'Preserve the successful path; make the expected failure path explicit and testable.',
    Maintainability: 'Keep observable behavior identical while making the risky code easier to change correctly.',
    'Clean code': 'Keep public behavior and imports stable; make only the smallest cleanup needed to remove the signal.',
    Foundations: 'Do not change runtime behavior; remove or clarify only the development residue identified by the scan.',
    'Project cleanup': 'Remove the artifact only after confirming that tooling and repository conventions do not require it.',
    'Runtime safety': 'Preserve supported inputs while bounding or validating the risky runtime path.',
    Accessibility: 'Preserve the interaction while ensuring the affected element has a meaningful accessible alternative.'
  };
  return contracts[group] || `Resolve ${issue.reason.toLowerCase()} without changing behavior outside the flagged path.`;
}

async function findRepairRelatedFiles(project, issue) {
  const basename = path.basename(issue.file).replace(path.extname(issue.file), '');
  const importNeedle = issue.file.replace(path.extname(issue.file), '').replace(/^\.\//, '');
  const candidates = project.files.filter(file => file.relative !== issue.file && !/node_modules|\.min\./i.test(file.relative));
  const related = await mapWithConcurrency(candidates, 10, async file => {
    try {
      const stat = await fs.stat(file.full);
      if (stat.size > 384 * 1024) return null;
      const source = await fs.readFile(file.full, 'utf8');
      const isTest = /(?:^|[./_-])(test|tests|spec|__tests__)(?:[./_-]|$)/i.test(file.relative);
      const referencesTarget = basename.length > 2 && (source.includes(`./${importNeedle}`) || source.includes(`../${importNeedle}`) || source.includes(`'${basename}'`) || source.includes(`\"${basename}\"`));
      return referencesTarget || (isTest && source.includes(basename)) ? file.relative : null;
    } catch { return null; }
  });
  return related.filter(Boolean).sort((left, right) => left.localeCompare(right)).slice(0, 5);
}

async function getRepairGitHistory(root, file) {
  try {
    const raw = await simpleGit(root).raw(['log', '--max-count=12', '--format=%h%x00%aI%x00%s', '--', file]);
    const entries = raw.trim().split(/\r?\n/).filter(Boolean).map(line => {
      const [hash, date, subject] = line.split('\0');
      return { hash, date, subject };
    }).filter(item => item.hash);
    return { commits: entries.length, latest: entries[0] || null };
  } catch { return { commits: 0, latest: null }; }
}

async function getRepairVerificationCommands(root) {
  try {
    const manifest = JSON.parse(await fs.readFile(path.join(root, 'package.json'), 'utf8'));
    const scripts = manifest.scripts || {};
    return ['test', 'lint', 'typecheck', 'check'].filter(name => scripts[name]).slice(0, 2).map(name => `npm run ${name}`);
  } catch { return []; }
}

async function captureRepairBaseline(root) {
  try {
    const status = await simpleGit(root).status();
    return {
      available: true,
      clean: status.isClean(),
      files: new Map(status.files.map(file => [file.path.replaceAll('\\', '/'), `${file.index}:${file.working_dir}`]))
    };
  } catch { return { available: false, clean: false, files: new Map() }; }
}

async function buildRepairReceipt(root, plan, baseline) {
  if (!baseline?.available) return { available: false, reason: 'Git working-tree evidence is unavailable for this project.' };
  try {
    const status = await simpleGit(root).status();
    const current = new Map(status.files.map(file => [file.path.replaceAll('\\', '/'), `${file.index}:${file.working_dir}`]));
    const allPaths = new Set([...baseline.files.keys(), ...current.keys()]);
    const changedFiles = [...allPaths].filter(file => baseline.files.get(file) !== current.get(file)).sort();
    const allowed = new Set(plan.scope.allow.map(file => file.replaceAll('\\', '/')));
    const outOfScope = changedFiles.filter(file => !allowed.has(file));
    return {
      available: true,
      isolated: baseline.clean,
      changedFiles,
      outOfScope,
      scopeStatus: baseline.clean ? (outOfScope.length ? 'outside-scope' : 'within-scope') : 'baseline-dirty',
      generatedAt: new Date().toISOString(),
      note: baseline.clean
        ? 'The repository was clean before the repair, so this receipt isolates files changed by the approved task.'
        : 'The repository already had uncommitted work, so scope evidence is advisory. Commit or stash first for an isolated receipt.'
    };
  } catch { return { available: false, reason: 'Code Redox could not read Git working-tree evidence after the repair.' }; }
}

async function prettierFormatFile(file) {
  try {
    const prettier = await import('prettier');
    const source = await fs.readFile(file.full, 'utf8');
    const info = await prettier.getFileInfo(file.full, { ignorePath: false });
    if (info.ignored || !info.inferredParser) return null;
    const config = (await prettier.resolveConfig(file.full)) || {};
    const output = await prettier.format(source, { ...config, filepath: file.full });
    return { source, output, changed: source !== output };
  } catch { return null; }
}

function firstChangedLine(before, after) {
  const original = before.split(/\r?\n/);
  const formatted = after.split(/\r?\n/);
  const length = Math.min(original.length, formatted.length);
  for (let index = 0; index < length; index += 1) if (original[index] !== formatted[index]) return index + 1;
  return length + 1;
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
async function runCodexCli(cwd, prompt, onProgress, retriedAfterUpdate = false, options = {}) {
  const candidates = codexCliCandidates();
  const errors = [];
  for (const command of candidates) try {
    return await runCodexCommand(command, ['exec', '--sandbox', options.sandbox || 'workspace-write', '--skip-git-repo-check', prompt], cwd, onProgress, 'Codex finished successfully.');
  } catch (error) {
    const message = error.message || String(error);
    if (!retriedAfterUpdate && /requires a newer version of Codex/i.test(message)) {
      onProgress?.({ status: 'output', text: 'Codex needs an update for this model. Updating the local CLI, then retrying…' });
      try {
        await runCodexCommand(command, ['update'], cwd, onProgress, 'Codex CLI updated. Retrying the fix…');
      } catch (updateError) {
        if (!/Could not detect the Codex installation method/i.test(updateError.message || '')) throw updateError;
        onProgress?.({ status: 'output', text: 'The desktop-managed CLI cannot update itself. Downloading the latest official Codex CLI for this fix…' });
        return runLatestCodexCli(cwd, prompt, onProgress, options);
      }
      return runCodexCli(cwd, prompt, onProgress, true, options);
    }
    if (!/ENOENT|not recognized as an internal or external command/i.test(message)) throw new Error(`Codex CLI failed. ${message}`);
    errors.push(message);
  }
  throw new Error(`Unable to run the Codex CLI. Install the standalone Codex CLI or set CODEX_CLI_PATH. ${errors.join(' | ')}`.trim());
}
async function runLatestCodexCli(cwd, prompt, onProgress, options = {}) {
  const npxScript = npxCliScript();
  if (!npxScript) throw new Error('Codex needs an update, but npm is unavailable to download the latest CLI. Update the Codex desktop app and try again.');
  const args = [npxScript, '--yes', '@openai/codex@latest', 'exec', '--sandbox', options.sandbox || 'workspace-write', '--skip-git-repo-check', prompt];
  return runCodexCommand(process.execPath, args, cwd, onProgress, 'Codex finished successfully using the latest CLI.', { env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
}
function runCodexCommand(command, args, cwd, onProgress, completedText, options = {}) {
  return new Promise((resolve, reject) => {
    const isBatch = process.platform === 'win32' && /\.cmd$/i.test(command);
    const executable = isBatch ? (process.env.ComSpec || process.env.COMSPEC || 'cmd.exe') : command;
    const commandLine = isBatch ? [command, ...args].map(quoteForCmd).join(' ') : null;
    const child = spawn(executable, isBatch ? ['/d', '/s', '/c', commandLine] : args, { ...options, cwd, shell: false, windowsHide: true, detached: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    onProgress?.({ status: 'started', text: `> ${path.basename(command)} ${args.slice(0, 4).join(' ')}` });
    child.stdout?.on('data', data => { const text = data.toString(); stdout += text; onProgress?.({ status: 'output', text: text.slice(-4000) }); });
    child.stderr?.on('data', data => { const text = data.toString(); stderr += text; onProgress?.({ status: 'output', text: text.slice(-4000) }); });
    child.on('error', error => reject(error));
    child.on('close', code => code === 0 ? (onProgress?.({ status: 'completed', text: completedText }), resolve({ stdout })) : reject(new Error(stderr || `Codex exited with code ${code}.`)));
  });
}
function quoteForCmd(value) {
  return `"${String(value).replace(/["^&|<>()%!]/g, character => character === '%' ? '%%' : `^${character}`)}"`;
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
function timeMachinePriority(issue) {
  return ({ secrets: 8, 'sql-injection': 8, 'path-traversal': 8, 'xss-sinks': 8, 'unsafe-deserialization': 8, 'duplicate-code': 5, 'dead-code': 4, 'package-integrity': 4, 'logic-conditions': 4, 'error-handling': 4 }[issue.type] || 1);
}
function gateRiskWeight(type) {
  return ({
    secrets: 14, 'sql-injection': 13, 'path-traversal': 12, 'xss-sinks': 13, 'command-injection': 13,
    'unsafe-file-uploads': 12, 'unsafe-deserialization': 11, 'tls-validation': 11, 'prototype-pollution': 11,
    'unvalidated-redirects': 10, 'weak-cryptography': 10, 'insecure-randomness': 10, 'insecure-defaults': 10,
    'logic-conditions': 8, 'error-handling': 8, 'unsafe-operations': 10, 'regex-dos': 10,
    'package-integrity': 6, 'complex-logic': 7, 'broad-exception-handling': 7
  }[type] || 3);
}
async function mergeGateCommands(root) {
  const manifestPath = path.join(root, 'package.json');
  try {
    const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    const scripts = manifest.scripts || {};
    const preferred = ['test', 'lint', 'typecheck', 'build'].filter(name => scripts[name]).map(name => `npm run ${name}`);
    return preferred.length ? preferred : ['Review the Git diff', 'Run the project’s focused verification command'];
  } catch {
    return ['Review the Git diff', 'Run the project’s focused verification command'];
  }
}
function recentFileChangeStats(logOutput) {
  const fileChanges = new Map();
  let currentCommit = '';
  let commitsAnalyzed = 0;
  logOutput.split(/\r?\n/).forEach(line => {
    if (line.startsWith('__CRX_COMMIT__')) { currentCommit = line.slice('__CRX_COMMIT__'.length); commitsAnalyzed += 1; return; }
    const file = line.trim().replaceAll('\\', '/');
    if (!currentCommit || !file) return;
    const commits = fileChanges.get(file) || new Set();
    commits.add(currentCommit);
    fileChanges.set(file, commits);
  });
  return { fileChanges, commitsAnalyzed };
}
function makeForecast({ id, kind, confidence, priority, prediction, action, evidence, file = '' }) {
  return { id, kind, confidence, priority, prediction, action, evidence, file };
}
function awardStructures(file) {
  const isPython = /\.py$/i.test(file.file);
  if (isPython) return pythonAwardStructures(file);
  const found = [];
  const controls = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'else', 'try', 'do']);
  file.lines.forEach((line, index) => {
    const classMatch = line.match(/\b(?:class|interface)\s+([A-Za-z_$][\w$]*)[^\{]*\{/);
    if (classMatch) {
      const end = braceClosingLine(file.lines, index);
      if (end !== -1) found.push({ kind: 'class', name: classMatch[1], file: file.file, language: file.language, start: index + 1, end: end + 1, lines: end - index + 1, parameters: 0 });
      return;
    }
    const functionMatch = line.match(/(?:\bfunction\s+([\w$]+)|\b([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|\b([\w$]+)\s*\([^)]*\)\s*\{|\b(?:public|private|protected|static|async|final|synchronized|virtual|override|def)\s+[\w<>\[\],?\s]*\s+([\w$]+)\s*\([^)]*\)\s*\{)/);
    if (!functionMatch || !line.includes('{')) return;
    const name = functionMatch.slice(1).find(Boolean);
    if (!name || controls.has(name)) return;
    const end = braceClosingLine(file.lines, index);
    if (end !== -1) found.push({ kind: 'function', name, file: file.file, language: file.language, start: index + 1, end: end + 1, lines: end - index + 1, parameters: parameterCount(line) });
  });
  return found;
}
function pythonAwardStructures(file) {
  const found = [];
  file.lines.forEach((line, index) => {
    const match = line.match(/^(\s*)(?:async\s+)?(def|class)\s+([A-Za-z_]\w*)\b/);
    if (!match) return;
    const indent = match[1].replace(/\t/g, '    ').length;
    let end = index;
    for (let cursor = index + 1; cursor < file.lines.length; cursor += 1) {
      const candidate = file.lines[cursor];
      if (!candidate.trim() || /^\s*#/.test(candidate)) { end = cursor; continue; }
      const candidateIndent = candidate.match(/^\s*/)[0].replace(/\t/g, '    ').length;
      if (candidateIndent <= indent) break;
      end = cursor;
    }
    found.push({ kind: match[2] === 'class' ? 'class' : 'function', name: match[3], file: file.file, language: file.language, start: index + 1, end: end + 1, lines: end - index + 1, parameters: match[2] === 'class' ? 0 : parameterCount(line) });
  });
  return found;
}
function braceClosingLine(lines, start) {
  let depth = 0;
  for (let index = start; index < lines.length; index += 1) {
    const source = lines[index].replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
    depth += (source.match(/\{/g) || []).length;
    depth -= (source.match(/\}/g) || []).length;
    if (depth === 0 && index >= start) return index;
  }
  return -1;
}
function parameterCount(line) {
  const parameters = line.match(/\(([^)]*)\)/)?.[1] || '';
  return parameters.split(',').map(value => value.trim()).filter(value => value && !/^\*{1,2}\w+$/.test(value)).length;
}
function findingHotspotFor(issues, type) {
  const counts = new Map();
  issues.filter(issue => issue.type === type).forEach(issue => counts.set(issue.file, (counts.get(issue.file) || 0) + 1));
  return [...counts.entries()].sort((left, right) => right[1] - left[1])[0];
}
function formatAwardBytes(value) { return value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1048576).toFixed(1)} MB`; }
async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await worker(items[index]);
    }
  }));
  return results;
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
