import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';

const TIMEOUT_MS = 7000;
const USAGE_FILE = /\.(?:[cm]?js|jsx|tsx?|php|py|java|go|rs)$/i;
const CAPABILITY_GROUPS = [
  { id: 'http-client', label: 'HTTP client', packages: { JavaScript: ['axios', 'node-fetch', 'cross-fetch', 'got', 'ky', 'superagent', 'needle', 'undici', 'request'], PHP: ['guzzlehttp/guzzle', 'symfony/http-client', 'kriswallsmith/buzz'], Python: ['requests', 'httpx', 'aiohttp', 'urllib3'], Java: ['org.apache.httpcomponents:httpclient', 'com.squareup.okhttp3:okhttp', 'com.squareup.retrofit2:retrofit'] } },
  { id: 'date-time', label: 'date and time library', packages: { JavaScript: ['moment', 'dayjs', 'date-fns', 'luxon'], PHP: ['nesbot/carbon', 'cakephp/chronos'], Python: ['pendulum', 'arrow', 'maya'], Java: ['joda-time:joda-time', 'org.threeten:threetenbp'] } },
  { id: 'validation', label: 'validation library', packages: { JavaScript: ['zod', 'yup', 'joi', 'ajv', 'superstruct', 'valibot'], PHP: ['symfony/validator', 'respect/validation'], Python: ['pydantic', 'marshmallow', 'cerberus'], Java: ['org.hibernate.validator:hibernate-validator', 'javax.validation:validation-api'] } },
  { id: 'logging', label: 'logging library', packages: { JavaScript: ['winston', 'pino', 'bunyan', 'log4js'], PHP: ['monolog/monolog'], Python: ['loguru', 'structlog'], Java: ['ch.qos.logback:logback-classic', 'org.apache.logging.log4j:log4j-core'] } }
];

export async function discoverPackages(root, files) {
  const names = new Set(files.map(file => file.relative));
  const packages = [];
  const add = item => packages.push({ ...item, id: `${item.ecosystem}:${item.name}:${item.source}:${item.section}` });

  for (const file of files.filter(item => path.basename(item.relative) === 'package.json')) {
    try {
      const manifest = JSON.parse(await fs.readFile(file.full, 'utf8'));
      for (const [section, dependencies] of Object.entries({ dependencies: manifest.dependencies, devDependencies: manifest.devDependencies, peerDependencies: manifest.peerDependencies, optionalDependencies: manifest.optionalDependencies })) {
        for (const [name, version] of Object.entries(dependencies || {})) add({ ecosystem: 'JavaScript', name, version, source: file.relative, section, registry: 'npm' });
      }
    } catch { /* invalid manifest */ }
  }
  for (const file of files.filter(item => path.basename(item.relative) === 'composer.json')) {
    try {
      const manifest = JSON.parse(await fs.readFile(file.full, 'utf8'));
      for (const [section, dependencies] of Object.entries({ require: manifest.require, 'require-dev': manifest['require-dev'] })) {
        for (const [name, version] of Object.entries(dependencies || {})) if (!/^(?:php|ext-|lib-)/i.test(name)) add({ ecosystem: 'PHP', name, version, source: file.relative, section, registry: 'packagist' });
      }
    } catch { /* invalid manifest */ }
  }
  for (const file of files.filter(item => path.basename(item.relative) === 'pom.xml')) {
    try { parseMaven(await fs.readFile(file.full, 'utf8')).forEach(item => add({ ...item, ecosystem: 'Java', source: file.relative, section: 'dependency', registry: 'maven' })); } catch { /* unreadable pom */ }
  }
  for (const file of files.filter(item => /(?:^|\/)(?:build\.gradle|build\.gradle\.kts)$/i.test(item.relative))) {
    try { parseGradle(await fs.readFile(file.full, 'utf8')).forEach(item => add({ ...item, ecosystem: 'Java', source: file.relative, section: 'dependency', registry: 'maven' })); } catch { /* unreadable gradle file */ }
  }
  for (const file of files.filter(item => /(?:^|\/)requirements[^/]*\.txt$/i.test(item.relative))) {
    try { parseRequirements(await fs.readFile(file.full, 'utf8')).forEach(item => add({ ...item, ecosystem: 'Python', source: file.relative, section: 'dependency', registry: 'pypi' })); } catch { /* unreadable requirements */ }
  }
  for (const file of files.filter(item => path.basename(item.relative) === 'go.mod')) {
    try { parseGoMod(await fs.readFile(file.full, 'utf8')).forEach(item => add({ ...item, ecosystem: 'Go', source: file.relative, section: 'require', registry: 'go' })); } catch { /* unreadable go.mod */ }
  }
  for (const file of files.filter(item => path.basename(item.relative) === 'Cargo.toml')) {
    try { parseCargo(await fs.readFile(file.full, 'utf8')).forEach(item => add({ ...item, ecosystem: 'Rust', source: file.relative, section: 'dependency', registry: 'crates' })); } catch { /* unreadable Cargo manifest */ }
  }
  const usageSource = await readUsageSource(files);
  const discovered = uniquePackages(packages);
  const declarations = new Map();
  discovered.forEach(item => { const key = `${item.ecosystem}:${item.name.toLowerCase()}`; const matches = declarations.get(key) || []; matches.push(item); declarations.set(key, matches); });
  const capabilityOverlaps = findCapabilityOverlaps(discovered);
  return discovered.map(item => {
    const matches = declarations.get(`${item.ecosystem}:${item.name.toLowerCase()}`) || [];
    const duplicateLocations = matches.map(match => ({ source: match.source, section: match.section, version: match.version }));
    const duplicate = matches.length > 1;
    const versions = new Set(matches.map(match => normaliseComparableVersion(match.version)));
    const overlaps = capabilityOverlaps.get(item.id) || [];
    return { ...item, usage: packageIsUsed(item, usageSource) ? 'used' : 'unused', duplicate, duplicateKind: duplicate ? (versions.size > 1 ? 'version-conflict' : 'duplicate') : null, duplicateLocations, overlap: overlaps.length > 0, overlapGroups: overlaps };
  }).sort((left, right) => left.ecosystem.localeCompare(right.ecosystem) || left.name.localeCompare(right.name));
}

export async function addLatestVersions(packages) {
  return mapLimit(packages, 6, async item => {
    const release = await latestRelease(item).catch(() => null);
    return { ...item, latest: release?.version || null, latestUpdatedAt: release?.updatedAt || null };
  });
}

export async function managePackage(root, files, item, action) {
  if (!['update', 'uninstall'].includes(action)) throw new Error('Unsupported package action.');
  if (action === 'update' && !item.latest) throw new Error('The latest version is unavailable for this package.');
  if (item.ecosystem === 'JavaScript') return runJavaScriptPackageManager(root, files, item, action);
  if (item.ecosystem === 'PHP') return runProgram('composer', action === 'update' ? ['require', `${item.name}:${item.latest}`] : ['remove', item.name], root);
  if (item.ecosystem === 'Go') { if (action === 'update') return runProgram('go', ['get', `${item.name}@latest`], root); await runProgram('go', ['mod', 'edit', `-droprequire=${item.name}`], root); return runProgram('go', ['mod', 'tidy'], root); }
  if (item.ecosystem === 'Rust') return runProgram('cargo', action === 'update' ? ['add', `${item.name}@${item.latest}`] : ['remove', item.name], root);
  if (item.ecosystem === 'Python') return editRequirementsFile(root, item, action);
  if (item.ecosystem === 'Java') return editJavaDependency(root, item, action);
  throw new Error(`Package actions are unavailable for ${item.ecosystem}.`);
}

async function runJavaScriptPackageManager(root, files, item, action) {
  const manager = files.some(file => /(?:^|\/)pnpm-lock\.yaml$/i.test(file.relative)) ? 'pnpm' : files.some(file => /(?:^|\/)yarn\.lock$/i.test(file.relative)) ? 'yarn' : files.some(file => /(?:^|\/)(?:bun\.lockb|bun\.lock)$/i.test(file.relative)) ? 'bun' : 'npm';
  const versionedName = `${item.name}@${item.latest}`;
  if (action === 'uninstall') return runProgram(manager, [manager === 'npm' ? 'uninstall' : 'remove', item.name], root);
  const sectionArgs = item.section === 'devDependencies'
    ? (manager === 'pnpm' ? ['-D'] : manager === 'bun' ? ['--dev'] : ['--save-dev'])
    : item.section === 'peerDependencies' ? (manager === 'yarn' || manager === 'bun' ? ['--peer'] : ['--save-peer'])
      : item.section === 'optionalDependencies' ? (manager === 'yarn' || manager === 'bun' ? ['--optional'] : ['--save-optional']) : [];
  return runProgram(manager, [manager === 'npm' ? 'install' : 'add', versionedName, ...sectionArgs], root);
}

async function editRequirementsFile(root, item, action) {
  const sourcePath = path.join(root, item.source);
  const source = await fs.readFile(sourcePath, 'utf8');
  const name = escapeRegex(item.name);
  const pattern = new RegExp(`^(\\s*${name}(?:\\[[^\\]]+])?\\s*)(?:==|~=|>=|<=|>|<)\\s*[^\\s;,]+.*$`, 'gim');
  const updated = action === 'update' ? source.replace(pattern, `$1==${item.latest}`) : source.replace(pattern, '');
  if (updated === source) throw new Error(`Could not locate ${item.name} in ${item.source}.`);
  await fs.writeFile(sourcePath, updated.replace(/\n{3,}/g, '\n\n'), 'utf8');
  return { message: `${action === 'update' ? 'Updated' : 'Removed'} ${item.name} in ${item.source}.` };
}

async function editJavaDependency(root, item, action) {
  const sourcePath = path.join(root, item.source);
  const source = await fs.readFile(sourcePath, 'utf8');
  const [group, artifact] = item.name.split(':');
  let updated = source;
  if (/pom\.xml$/i.test(item.source)) {
    const dependency = /<dependency>([\s\S]*?)<\/dependency>/g;
    let changed = false;
    updated = source.replace(dependency, (block, body) => {
      if (xmlValue(body, 'groupId') !== group || xmlValue(body, 'artifactId') !== artifact) return block;
      changed = true;
      if (action === 'uninstall') return '';
      const property = xmlValue(body, 'version')?.match(/^\$\{(.+)}$/)?.[1];
      if (property) return block.replace(new RegExp(`(<${escapeRegex(property)}>\\s*)[^<]+(\\s*<\\/${escapeRegex(property)}>)`), `$1${item.latest}$2`);
      return /<version>/.test(block) ? block.replace(/(<version>\s*)[^<]+(\s*<\/version>)/, `$1${item.latest}$2`) : block.replace(/<\/dependency>/, `  <version>${item.latest}</version>\n</dependency>`);
    });
    if (!changed) throw new Error(`Could not locate ${item.name} in ${item.source}.`);
  } else {
    const notation = new RegExp(`(['"])${escapeRegex(item.name)}:[^'"]+\\1`, 'g');
    if (!notation.test(source)) throw new Error(`Could not locate ${item.name} in ${item.source}.`);
    updated = action === 'update' ? source.replace(notation, (_match, quote) => `${quote}${item.name}:${item.latest}${quote}`) : source.replace(/^.*['"]${escapeRegex(item.name)}:[^'"]+['"].*(?:\r?\n)?/gm, '');
  }
  await fs.writeFile(sourcePath, updated.replace(/\n{3,}/g, '\n\n'), 'utf8');
  return { message: `${action === 'update' ? 'Updated' : 'Removed'} ${item.name} in ${item.source}.` };
}
function runProgram(command, args, cwd) {
  const isWindows = process.platform === 'win32';
  const executable = isWindows ? `${command}.cmd` : command;
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { cwd, shell: isWindows, windowsHide: true });
    let stderr = '';
    child.stderr?.on('data', data => { stderr += data; });
    child.on('error', error => reject(error));
    child.on('close', code => code === 0 ? resolve({ message: `${command} completed successfully.` }) : reject(new Error(stderr || `${command} exited with code ${code}.`)));
  });
}

function parseMaven(source) {
  const properties = Object.fromEntries([...source.matchAll(/<([\w.-]+)>\s*([^<]+?)\s*<\/\1>/g)].map(([, key, value]) => [key, value.trim()]));
  return [...source.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].flatMap(([, body]) => {
    const group = xmlValue(body, 'groupId'); const artifact = xmlValue(body, 'artifactId'); let version = xmlValue(body, 'version'); const property = version?.match(/^\$\{(.+)}$/);
    if (property) version = properties[property[1]] || version;
    return group && artifact && version && !version.includes('${') ? [{ name: `${group}:${artifact}`, version, group, artifact }] : [];
  });
}
function parseGradle(source) { return [...source.matchAll(/(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*(?:\(\s*)?['"]([^:'"]+):([^:'"]+):([^'"\s)]+)['"]/g)].map(([, group, artifact, version]) => ({ name: `${group}:${artifact}`, version, group, artifact })); }
function parseRequirements(source) { return source.split(/\r?\n/).flatMap(line => { const match = line.replace(/\s*#.*$/, '').match(/^\s*([\w.-]+)(?:\[[^\]]+])?\s*(?:==|~=|>=|<=|>|<)\s*([^\s;,]+)/); return match ? [{ name: match[1], version: match[2] }] : []; }); }
function parseGoMod(source) { return source.split(/\r?\n/).flatMap(line => { const trimmed = line.replace(/\/\/.*$/, '').trim(); if (/^(?:module|go)\s/.test(trimmed) || trimmed === 'require (' || trimmed === ')') return []; const match = trimmed.replace(/^require\s+/, '').match(/^([\w.~/-]+)\s+(v[^\s]+)/); return match ? [{ name: match[1], version: match[2] }] : []; }); }
function parseCargo(source) { let dependencies = false; return source.split(/\r?\n/).flatMap(line => { if (/^\s*\[.*dependencies.*]\s*$/i.test(line)) { dependencies = true; return []; } if (/^\s*\[/.test(line)) dependencies = false; const match = dependencies && line.match(/^\s*([\w-]+)\s*=\s*['"]([^'"]+)['"]/); return match ? [{ name: match[1], version: match[2] }] : []; }); }
function xmlValue(source, tag) { return source.match(new RegExp(`<${tag}>\\s*([^<]+?)\\s*<\\/${tag}>`))?.[1]?.trim(); }
function uniquePackages(packages) { const seen = new Set(); return packages.filter(item => { const key = `${item.ecosystem}:${item.name}:${item.version}:${item.source}:${item.section}`; if (seen.has(key)) return false; seen.add(key); return true; }); }
function normaliseComparableVersion(version) { return String(version || '').replace(/^[~^v=<> ]+/, '').trim().toLowerCase(); }
function findCapabilityOverlaps(packages) {
  const overlaps = new Map();
  CAPABILITY_GROUPS.forEach(group => {
    Object.entries(group.packages).forEach(([ecosystem, names]) => {
      const matches = packages.filter(item => item.ecosystem === ecosystem && names.includes(item.name.toLowerCase()));
      const distinctNames = [...new Set(matches.map(item => item.name.toLowerCase()))];
      if (distinctNames.length < 2) return;
      matches.forEach(item => {
        const entries = overlaps.get(item.id) || [];
        entries.push({ id: group.id, label: group.label, packages: distinctNames });
        overlaps.set(item.id, entries);
      });
    });
  });
  return overlaps;
}

async function latestRelease(item) {
  if (item.registry === 'npm') { const data = await requestJson(`https://registry.npmjs.org/${encodeURIComponent(item.name)}`); const version = data['dist-tags']?.latest; return version ? { version, updatedAt: data.time?.[version] || null } : null; }
  if (item.registry === 'packagist') { const entry = (await requestJson(`https://repo.packagist.org/p2/${item.name}.json`)).packages?.[item.name]?.find(candidate => !/dev|alpha|beta|RC/i.test(candidate.version || '')); return entry ? { version: entry.version?.replace(/^v/, ''), updatedAt: entry.time || null } : null; }
  if (item.registry === 'maven') { const params = new URLSearchParams({ q: `g:"${item.group}" AND a:"${item.artifact}"`, rows: '1', wt: 'json' }); const entry = (await requestJson(`https://search.maven.org/solrsearch/select?${params}`)).response?.docs?.[0]; return entry?.latestVersion ? { version: entry.latestVersion, updatedAt: entry.timestamp ? new Date(entry.timestamp).toISOString() : null } : null; }
  if (item.registry === 'pypi') { const data = await requestJson(`https://pypi.org/pypi/${encodeURIComponent(item.name)}/json`); const version = data.info?.version; const uploads = data.releases?.[version] || []; return version ? { version, updatedAt: uploads.at(-1)?.upload_time_iso_8601 || null } : null; }
  if (item.registry === 'go') { const data = await requestJson(`https://proxy.golang.org/${item.name}/@latest`); return data.Version ? { version: data.Version, updatedAt: data.Time || null } : null; }
  if (item.registry === 'crates') { const entry = (await requestJson(`https://crates.io/api/v1/crates/${encodeURIComponent(item.name)}`)).crate; return entry?.max_version ? { version: entry.max_version, updatedAt: entry.updated_at || null } : null; }
  return null;
}
async function readUsageSource(files) { return (await Promise.all(files.filter(file => USAGE_FILE.test(file.relative)).map(file => fs.readFile(file.full, 'utf8').catch(() => '')))).join('\n'); }
function packageIsUsed(item, source) {
  if (!source) return false;
  if (item.ecosystem === 'JavaScript') return new RegExp(`(?:from\\s*|require\\s*\\(|import\\s*\\()(['"])${escapeRegex(item.name)}(?:/[^'"]*)?\\1`).test(source);
  if (item.ecosystem === 'PHP') return new RegExp(`\\buse\\s+${escapeRegex(item.name.split('/')[0]).replace(/\\\\/g, '\\\\')}`, 'i').test(source);
  if (item.ecosystem === 'Java') return new RegExp(`\\bimport\\s+${escapeRegex(item.group)}\\.`).test(source);
  if (item.ecosystem === 'Python') { const name = item.name.replace(/-/g, '_').split('.')[0]; return new RegExp(`\\b(?:from|import)\\s+${escapeRegex(name)}\\b`).test(source); }
  if (item.ecosystem === 'Go') return new RegExp(`['"]${escapeRegex(item.name)}(?:/[^'"]*)?['"]`).test(source);
  if (item.ecosystem === 'Rust') return new RegExp(`\\b(?:use|extern\\s+crate)\\s+${escapeRegex(item.name.replace(/-/g, '_'))}\\b`).test(source);
  return false;
}
function escapeRegex(value) { return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
async function requestJson(url) { const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), TIMEOUT_MS); try { const response = await fetch(url, { signal: controller.signal, headers: { accept: 'application/json' } }); if (!response.ok) throw new Error(`Registry returned ${response.status}`); return response.json(); } finally { clearTimeout(timer); } }
async function mapLimit(items, limit, mapper) { const results = []; let next = 0; await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const index = next; next += 1; results[index] = await mapper(items[index]); } })); return results; }
