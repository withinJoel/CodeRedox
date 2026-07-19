import fs from 'node:fs/promises';
import path from 'node:path';
const [root, filesArg] = process.argv.slice(2); const files = JSON.parse(filesArg);
const report = issue => process.stdout.write(`${JSON.stringify({ type: 'issue', issue })}\n`);
for (const file of files) {
  if (!/\.(?:[cm]?js|jsx|tsx?|py|java|go|rs|css|html|md|json|ya?ml|sh)$/i.test(file)) continue;
  try {
    const text = await fs.readFile(path.join(root, file), 'utf8'); const lines = text.split(/\r?\n/); let blanks = 0;
    lines.forEach((line, index) => { const lineNo = index + 1; if (/[ \t]+$/.test(line)) report({ file, line: lineNo, reason: 'Trailing whitespace.' }); if (/^(?=\s*\S)(?=.*\t)(?=.* {2,})/.test(line)) report({ file, line: lineNo, reason: 'Mixed tabs and spaces in indentation.' }); if (/^\s*$/.test(line)) { blanks += 1; if (blanks === 3) report({ file, line: lineNo - 2, endLine: lineNo, reason: 'Three or more consecutive blank lines.' }); } else blanks = 0; });
    if (text.length && !text.endsWith('\n')) report({ file, line: lines.length, reason: 'Missing final newline.' });
  } catch { /* unreadable file */ }
}
