import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { discoverPackages } from '../src/main/package-service.js';

test('discovers package manifests across supported ecosystems', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-packages-'));
  const fixtures = {
    'package.json': JSON.stringify({ dependencies: { zod: '^3.0.0' }, devDependencies: { vite: '^5.0.0' } }),
    'composer.json': JSON.stringify({ require: { 'guzzlehttp/guzzle': '^7.0', php: '^8.2' } }),
    'pom.xml': '<project><properties><junit.version>5.10.0</junit.version></properties><dependencies><dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>${junit.version}</version></dependency></dependencies></project>',
    'requirements.txt': 'requests==2.31.0\n',
    'go.mod': 'module example.com/demo\n\nrequire github.com/pkg/errors v0.9.1\n',
    'Cargo.toml': '[dependencies]\nserde = "1.0"\n',
    'index.js': "import { z } from 'zod';\n",
    'Example.java': 'import org.junit.jupiter.api.Test;\n',
    'index.php': '<?php use GuzzleHttp\\Client;\n',
    'main.py': 'import requests\n',
    'main.go': 'import "github.com/pkg/errors"\n',
    'main.rs': 'use serde::Serialize;\n'
  };
  try {
    await Promise.all(Object.entries(fixtures).map(([name, content]) => fs.writeFile(path.join(root, name), content)));
    const files = Object.keys(fixtures).map(relative => ({ relative, full: path.join(root, relative) }));
    const packages = await discoverPackages(root, files);
    assert.deepEqual(packages.map(item => [item.ecosystem, item.name, item.version]), [
      ['Go', 'github.com/pkg/errors', 'v0.9.1'],
      ['Java', 'org.junit.jupiter:junit-jupiter', '5.10.0'],
      ['JavaScript', 'vite', '^5.0.0'],
      ['JavaScript', 'zod', '^3.0.0'],
      ['PHP', 'guzzlehttp/guzzle', '^7.0'],
      ['Python', 'requests', '2.31.0'],
      ['Rust', 'serde', '1.0']
    ]);
    assert.deepEqual(Object.fromEntries(packages.map(item => [item.name, item.usage])), {
      'github.com/pkg/errors': 'used',
      'org.junit.jupiter:junit-jupiter': 'used',
      vite: 'unused',
      zod: 'used',
      'guzzlehttp/guzzle': 'used',
      requests: 'used',
      serde: 'used'
    });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('marks repeated package declarations and version conflicts', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-package-duplicates-'));
  const fixtures = {
    'package.json': JSON.stringify({ dependencies: { zod: '^3.0.0' }, devDependencies: { vite: '^5.0.0' } }),
    'packages/admin/package.json': JSON.stringify({ dependencies: { zod: '^3.0.0', vite: '^6.0.0' } })
  };
  try {
    await Promise.all(Object.entries(fixtures).map(async ([relative, content]) => {
      const target = path.join(root, relative);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, content);
    }));
    const files = Object.keys(fixtures).map(relative => ({ relative, full: path.join(root, relative) }));
    const packages = await discoverPackages(root, files);
    const zod = packages.filter(item => item.name === 'zod');
    const vite = packages.filter(item => item.name === 'vite');
    assert.equal(zod.length, 2);
    assert.ok(zod.every(item => item.duplicate && item.duplicateKind === 'duplicate'));
    assert.ok(vite.every(item => item.duplicate && item.duplicateKind === 'version-conflict'));
    assert.ok(vite.every(item => item.duplicateLocations.length === 2));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('marks packages with an overlapping capability as duplicate functionality', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-redox-package-overlap-'));
  const manifest = JSON.stringify({ dependencies: { axios: '^1.0.0', 'node-fetch': '^3.0.0' } });
  try {
    await fs.writeFile(path.join(root, 'package.json'), manifest);
    const packages = await discoverPackages(root, [{ relative: 'package.json', full: path.join(root, 'package.json') }]);
    const httpClients = packages.filter(item => ['axios', 'node-fetch'].includes(item.name));
    assert.equal(httpClients.length, 2);
    assert.ok(httpClients.every(item => item.overlap));
    assert.ok(httpClients.every(item => item.overlapGroups.some(group => group.id === 'http-client')));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
