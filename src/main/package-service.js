import fs from 'node:fs/promises';
import path from 'node:path';

const TIMEOUT_MS = 7000;
const USAGE_FILE = /\.(?:[cm]?js|jsx|tsx?|php|py|java|go|rs)$/i;

export async function discoverPackages(root, files) {
  const names = new Set(files.map(file => file.relative));
  const packages = [];
  const add = item => packages.push({ ...item, id: `${item.ecosystem}:${item.name}:${item.source}` });

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
  return uniquePackages(packages).map(item => ({ ...item, usage: packageIsUsed(item, usageSource) ? 'used' : 'unused' })).sort((left, right) => left.ecosystem.localeCompare(right.ecosystem) || left.name.localeCompare(right.name));
}

export async function addLatestVersions(packages) {
  return mapLimit(packages, 6, async item => {
    const release = await latestRelease(item).catch(() => null);
    return { ...item, latest: release?.version || null, latestUpdatedAt: release?.updatedAt || null };
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
function uniquePackages(packages) { const seen = new Set(); return packages.filter(item => { const key = `${item.ecosystem}:${item.name}:${item.version}:${item.source}`; if (seen.has(key)) return false; seen.add(key); return true; }); }

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
