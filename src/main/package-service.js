import fs from 'node:fs/promises';
import path from 'node:path';

const TIMEOUT_MS = 7000;

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
  return uniquePackages(packages).sort((left, right) => left.ecosystem.localeCompare(right.ecosystem) || left.name.localeCompare(right.name));
}

export async function addLatestVersions(packages) {
  return mapLimit(packages, 6, async item => ({ ...item, latest: await latestVersion(item).catch(() => null) }));
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

async function latestVersion(item) {
  if (item.registry === 'npm') return (await requestJson(`https://registry.npmjs.org/${encodeURIComponent(item.name)}/latest`)).version;
  if (item.registry === 'packagist') { const data = await requestJson(`https://repo.packagist.org/p2/${item.name}.json`); return data.packages?.[item.name]?.find(entry => !/dev|alpha|beta|RC/i.test(entry.version || ''))?.version?.replace(/^v/, '') || null; }
  if (item.registry === 'maven') { const params = new URLSearchParams({ q: `g:"${item.group}" AND a:"${item.artifact}"`, rows: '1', wt: 'json' }); return (await requestJson(`https://search.maven.org/solrsearch/select?${params}`)).response?.docs?.[0]?.latestVersion || null; }
  if (item.registry === 'pypi') return (await requestJson(`https://pypi.org/pypi/${encodeURIComponent(item.name)}/json`)).info?.version || null;
  if (item.registry === 'go') return (await requestJson(`https://proxy.golang.org/${item.name}/@latest`)).Version || null;
  if (item.registry === 'crates') return (await requestJson(`https://crates.io/api/v1/crates/${encodeURIComponent(item.name)}`)).crate?.max_version || null;
  return null;
}
async function requestJson(url) { const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), TIMEOUT_MS); try { const response = await fetch(url, { signal: controller.signal, headers: { accept: 'application/json' } }); if (!response.ok) throw new Error(`Registry returned ${response.status}`); return response.json(); } finally { clearTimeout(timer); } }
async function mapLimit(items, limit, mapper) { const results = []; let next = 0; await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => { while (next < items.length) { const index = next; next += 1; results[index] = await mapper(items[index]); } })); return results; }
