import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { deleteEmptyArtifact, findEmptyArtifacts } from '../src/main/empty-artifact-service.js';

test('finds and safely deletes only empty files and folders', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-empty-'));
  try {
    await fs.writeFile(path.join(root, 'empty.txt'), '');
    await fs.writeFile(path.join(root, 'kept.txt'), 'content');
    await fs.mkdir(path.join(root, 'empty-folder'));
    await fs.mkdir(path.join(root, 'full-folder'));
    await fs.writeFile(path.join(root, 'full-folder', 'item.txt'), 'content');
    const files = [{ relative: 'empty.txt', full: path.join(root, 'empty.txt') }, { relative: 'kept.txt', full: path.join(root, 'kept.txt') }, { relative: 'full-folder/item.txt', full: path.join(root, 'full-folder', 'item.txt') }];
    const artifacts = await findEmptyArtifacts(root, files);
    assert.deepEqual(artifacts, [{ file: 'empty.txt', kind: 'file' }, { file: 'empty-folder', kind: 'folder' }]);
    await deleteEmptyArtifact(root, 'empty.txt', 'file');
    await deleteEmptyArtifact(root, 'empty-folder', 'folder');
    await assert.rejects(() => deleteEmptyArtifact(root, 'full-folder', 'folder'), /no longer empty/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
