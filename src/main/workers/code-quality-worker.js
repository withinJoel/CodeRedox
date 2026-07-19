import fs from 'node:fs/promises';
import path from 'node:path';

const [root, filesArg, rule] = process.argv.slice(2);
const files = JSON.parse(await fs.readFile(filesArg, 'utf8'));
const SOURCE_FILE = /\.(?:[cm]?js|jsx|tsx?|mjs|cjs)$/i;
const SECRET_FILE = /(?:\.(?:[cm]?js|jsx|tsx?|mjs|cjs|json|ya?ml|toml|ini|conf|config)$|(?:^|\/)(?:\.env(?:\..*)?|\.npmrc|\.pypirc|id_rsa|credentials(?:\.[\w-]+)?|secrets?(?:\.[\w-]+)?))$/i;
const emit = issue => process.stdout.write(`${JSON.stringify({ type: 'issue', issue })}\n`);

function inspect(ruleName, lines) {
  switch (ruleName) {
    case 'debug-code': return findDebugCode(lines);
    case 'todo-debt': return findTodoDebt(lines);
    case 'magic-values': return findMagicValues(lines);
    case 'long-functions': return findLongFunctions(lines);
    case 'complex-logic': return findComplexLogic(lines);
    case 'logic-conditions': return findLogicConditions(lines);
    case 'error-handling': return findEmptyCatchBlocks(lines);
    case 'secrets': return findSecrets(lines);
    case 'unsafe-operations': return findUnsafeOperations(lines);
    default: return [];
  }
}

function findSecrets(lines) {
  const findings = [];
  const seen = new Set();
  const add = (line, symbol, reason) => {
    const key = `${line}:${symbol}`;
    if (!seen.has(key)) { seen.add(key); findings.push({ line, symbol, reason }); }
  };
  lines.forEach((line, index) => {
    const lineNo = index + 1;
    if (/-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----/.test(line)) add(lineNo, 'Private key', 'Private key material is embedded in the project.');
    let matchedSignature = false;
    for (const signature of secretSignatures) {
      if (signature.pattern.test(line)) { matchedSignature = true; add(lineNo, signature.name, `${signature.name} appears to be hard-coded.`); }
    }
    const assignment = line.match(/\b([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY)[A-Z0-9_]*)\b\s*[:=]\s*['"]?([^'"\s,}#]+)['"]?/i);
    if (!matchedSignature && assignment && looksLikeSecretValue(assignment[2])) add(lineNo, assignment[1], `Sensitive variable ${assignment[1]} has a hard-coded value.`);
  });
  return findings;
}

const secretSignatures = [
  { name: 'OpenAI API key', pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/ },
  { name: 'GitHub token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: 'GitLab token', pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { name: 'AWS access key', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { name: 'Google API key', pattern: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { name: 'Stripe secret key', pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { name: 'npm token', pattern: /\bnpm_[A-Za-z0-9]{30,}\b/ },
  { name: 'SendGrid API key', pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Twilio API key', pattern: /\bSK[a-f0-9]{32}\b/i }
];

function looksLikeSecretValue(value) {
  if (!value || value.length < 8) return false;
  if (/^(?:\$\{|process\.env(?:\.|$)|env\.|your[_-]?|example|placeholder|replace|change[_-]?me|todo|null|undefined)/i.test(value)) return false;
  return /[A-Za-z]/.test(value) && (/[0-9]/.test(value) || /[._\-/+=]/.test(value) || value.length >= 16);
}

function findDebugCode(lines) {
  return lines.flatMap((line, index) => {
    const code = codeOnly(line);
    if (/\bdebugger\s*;?/.test(code)) return [{ line: index + 1, reason: 'Debugger statement left in source.' }];
    if (/\bconsole\.(?:log|debug|info|table|trace)\s*\(/.test(code)) return [{ line: index + 1, reason: 'Console debugging call left in source.' }];
    return [];
  });
}

function findTodoDebt(lines) {
  return lines.flatMap((line, index) => {
    const marker = line.match(/(?:\/\/|\/\*|\*)\s*(TODO|FIXME|HACK|XXX)\b\s*:?\s*(.*)/i);
    return marker ? [{ line: index + 1, symbol: marker[1].toUpperCase(), reason: `${marker[1].toUpperCase()} note should be resolved, scheduled, or linked to tracked work.` }] : [];
  });
}

function findMagicValues(lines) {
  return lines.flatMap((line, index) => {
    const code = codeOnly(line);
    if (!isMeaningfulNumericContext(code)) return [];
    const values = [...code.matchAll(/(?<![\w.$])(-?\d+(?:\.\d+)?)(?![\w.])/g)]
      .map(match => Number(match[1]))
      .filter(value => ![0, 1, -1, 2, 10, 100, 1000].includes(value));
    return values.length ? [{ line: index + 1, symbol: values.slice(0, 3).join(', '), reason: `Literal value${values.length > 1 ? 's' : ''} ${values.slice(0, 3).join(', ')} ${values.length > 1 ? 'appear' : 'appears'} inline. Name a constant when the value carries domain meaning.` }] : [];
  });
}

function isMeaningfulNumericContext(line) {
  return /(?:[=!<>]=?|[-+*/%]=?|\b(?:setTimeout|setInterval|slice|substring|indexOf|Math\.|Date\.|Array\.)\b)/.test(line);
}

function findLongFunctions(lines) {
  return functionsIn(lines).flatMap(fn => {
    const length = fn.end - fn.start + 1;
    return length > 75 ? [{ line: fn.start, endLine: fn.end, symbol: fn.name, reason: `Function spans ${length} lines. Split distinct responsibilities into focused helpers.` }] : [];
  });
}

function findComplexLogic(lines) {
  return functionsIn(lines).flatMap(fn => {
    const source = lines.slice(fn.start - 1, fn.end).join('\n');
    const branches = (source.match(/\b(?:if|else\s+if|for|while|case|catch)\b|\?\s*[^.:]/g) || []).length;
    const nesting = maxNesting(lines.slice(fn.start - 1, fn.end));
    if (branches < 7 && nesting < 4) return [];
    const detail = branches >= 7 ? `${branches} decision points` : `${nesting} nested blocks`;
    return [{ line: fn.start, endLine: fn.end, symbol: fn.name, reason: `Complex control flow (${detail}). Use guard clauses or extract a smaller decision-focused helper.` }];
  });
}

function findLogicConditions(lines) {
  return lines.flatMap((line, index) => {
    const condition = conditionFor(codeOnly(line));
    if (!condition) return [];
    if (/(?<![=!<>])=(?!=)/.test(condition)) return [{ line: index + 1, reason: 'Assignment inside a condition is likely unintended. Use an explicit comparison or assign before the condition.' }];
    if (/^\s*(?:true|false)\s*$/.test(condition)) return [{ line: index + 1, reason: 'Constant condition makes one branch permanently unreachable.' }];
    if (/(?:===|!==|==|!=)\s*NaN\b|\bNaN\s*(?:===|!==|==|!=)/.test(condition)) return [{ line: index + 1, reason: 'NaN comparisons are never reliable. Use Number.isNaN(value) instead.' }];
    if (/\.indexOf\s*\([^)]*\)\s*$/.test(condition)) return [{ line: index + 1, reason: 'Using indexOf directly as a condition misclassifies index 0 and -1. Compare the result explicitly.' }];
    return [];
  });
}

function findEmptyCatchBlocks(lines) {
  const issues = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\bcatch\s*(?:\([^)]*\))?\s*\{/.test(lines[index])) continue;
    const openingIndex = lines[index].indexOf('{', lines[index].indexOf('catch'));
    const end = closingLine(lines, index, openingIndex);
    if (end === -1) continue;
    const rawBody = end === index
      ? lines[index].slice(openingIndex + 1, lines[index].lastIndexOf('}'))
      : lines.slice(index + 1, end).join('\n');
    const body = rawBody.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '').trim();
    if (!body) issues.push({ line: index + 1, endLine: end + 1, reason: 'Empty catch block swallows errors silently. Handle, log, or deliberately document the recovery.' });
  }
  return issues;
}

function findUnsafeOperations(lines) {
  return lines.flatMap((line, index) => {
    const code = codeOnly(line);
    if (/\beval\s*\(/.test(code)) return [{ line: index + 1, symbol: 'eval', reason: 'Dynamic eval obscures control flow and can execute untrusted input.' }];
    if (/\bnew\s+Function\s*\(/.test(code)) return [{ line: index + 1, symbol: 'Function', reason: 'Dynamic Function construction obscures control flow and can execute untrusted input.' }];
    if (/\b(?:exec|execSync)\s*\(/.test(code)) return [{ line: index + 1, symbol: 'exec', reason: 'Shell execution needs strict input validation and an explicit command boundary.' }];
    return [];
  });
}

function functionsIn(lines) {
  const found = [];
  const controlKeywords = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'else', 'try', 'do']);
  const pattern = /(?:\bfunction\s+([\w$]+)|\b([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|\b([\w$]+)\s*\([^)]*\)\s*\{)/;
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match || !lines[index].includes('{')) continue;
    const end = closingLine(lines, index);
    const name = match[1] || match[2] || match[3] || 'anonymous function';
    if (end !== -1 && !controlKeywords.has(name)) found.push({ name, start: index + 1, end: end + 1 });
  }
  return found;
}

function closingLine(lines, start, startColumn = 0) {
  let depth = 0;
  for (let index = start; index < lines.length; index += 1) {
    const source = index === start ? lines[index].slice(startColumn) : lines[index];
    const cleaned = source.replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
    depth += (cleaned.match(/\{/g) || []).length;
    depth -= (cleaned.match(/\}/g) || []).length;
    if (depth === 0) return index;
  }
  return -1;
}

function maxNesting(lines) {
  let depth = 0;
  let maximum = 0;
  for (const line of lines) {
    depth += (line.match(/\{/g) || []).length;
    maximum = Math.max(maximum, depth);
    depth -= (line.match(/\}/g) || []).length;
  }
  return Math.max(0, maximum - 1);
}

function codeOnly(line) {
  return line
    .replace(/\/\/.*$/, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '');
}

function conditionFor(line) {
  const start = line.search(/\b(?:if|while)\s*\(/);
  if (start === -1) return '';
  const opening = line.indexOf('(', start);
  let depth = 0;
  for (let index = opening; index < line.length; index += 1) {
    if (line[index] === '(') depth += 1;
    if (line[index] === ')') {
      depth -= 1;
      if (depth === 0) return line.slice(opening + 1, index);
    }
  }
  return '';
}

for (const file of files) {
  if (!(SOURCE_FILE.test(file) || (rule === 'secrets' && SECRET_FILE.test(file)))) continue;
  try {
    const text = await fs.readFile(path.join(root, file), 'utf8');
    const lines = text.split(/\r?\n/);
    for (const issue of inspect(rule, lines)) emit({ file, ...issue });
  } catch {
    // Skip files that cannot be decoded as source text.
  }
}
