import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const worker = path.resolve('src/main/workers/code-quality-worker.js');

async function scan(rule, source) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-rule-'));
  try {
    await fs.writeFile(path.join(root, 'sample.js'), source);
    const fileList = path.join(root, 'files.json');
    await fs.writeFile(fileList, JSON.stringify(['sample.js']));
    const result = spawnSync(process.execPath, [worker, root, fileList, rule], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim() ? result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line).issue) : [];
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

test('flags high-confidence suspicious conditions at their source lines', async () => {
  const issues = await scan('logic-conditions', `
if (enabled = true) run();
while (false) wait();
if (value === NaN) retry();
if (items.indexOf(item)) use(item);
`);
  assert.deepEqual(issues.map(issue => issue.line), [2, 3, 4, 5]);
});

test('does not mistake normal loop assignments or source text for code issues', async () => {
  const conditions = await scan('logic-conditions', 'for (let index = 0; index < items.length; index += 1) use(items[index]);');
  const debug = await scan('debug-code', 'const documentation = "Call console.log only while debugging";');
  const todos = await scan('todo-debt', 'const note = "TODO: this is user-visible text";');
  assert.equal(conditions.length, 0);
  assert.equal(debug.length, 0);
  assert.equal(todos.length, 0);
});

test('flags an empty catch but not a one-line recovery', async () => {
  const empty = await scan('error-handling', 'try { work(); } catch (error) {}');
  const recovered = await scan('error-handling', 'try { work(); } catch (error) { return null; }');
  assert.equal(empty.length, 1);
  assert.equal(recovered.length, 0);
});

test('finds common tokens and hard-coded secret variables without exposing values', async () => {
  const issues = await scan('secrets', `
const OPENAI_API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890';
const servicePassword = 'mY-S3cret-value-123';
const API_KEY = process.env.API_KEY;
`);
  assert.deepEqual(issues.map(issue => issue.line), [2, 3]);
  assert.equal(issues[0].symbol, 'OpenAI API key');
});
