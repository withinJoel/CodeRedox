import fs from 'node:fs/promises';
import path from 'node:path';

const EXCLUDED_DIRECTORIES = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'coverage']);

export async function findEmptyArtifacts(root, files) {
  const emptyFiles = [];
  for (const file of files) {
    try { if ((await fs.stat(file.full)).size === 0) emptyFiles.push({ file: file.relative, kind: 'file' }); } catch { /* file changed while scanning */ }
  }
  const emptyFolders = [];
  await walkFolders(root, root, emptyFolders);
  return [...emptyFiles, ...emptyFolders];
}

export async function deleteEmptyArtifact(root, relative, kind) {
  const target = safeTarget(root, relative);
  const stat = await fs.stat(target);
  if (kind === 'file') {
    if (!stat.isFile() || stat.size !== 0) throw new Error('The file is no longer empty.');
    await fs.rm(target);
    return;
  }
  if (kind === 'folder') {
    if (!stat.isDirectory() || (await fs.readdir(target)).length !== 0) throw new Error('The folder is no longer empty.');
    await fs.rmdir(target);
    return;
  }
  throw new Error('Unsupported cleanup target.');
}

async function walkFolders(root, directory, results) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || EXCLUDED_DIRECTORIES.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    const children = await fs.readdir(full, { withFileTypes: true });
    if (children.length === 0) {
      results.push({ file: path.relative(root, full).replaceAll('\\', '/'), kind: 'folder' });
    } else {
      await walkFolders(root, full, results);
    }
  }
}

function safeTarget(root, relative) {
  const resolvedRoot = path.resolve(root);
  const target = path.resolve(resolvedRoot, relative);
  if (target === resolvedRoot || !target.startsWith(`${resolvedRoot}${path.sep}`)) throw new Error('Cleanup target is outside the opened project.');
  return target;
}
