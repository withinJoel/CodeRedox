import fs from 'node:fs/promises';
import path from 'node:path';

const [root, filesArg, rule] = process.argv.slice(2);
const files = JSON.parse(await fs.readFile(filesArg, 'utf8'));
const SOURCE_FILE = /\.(?:[cm]?js|jsx|tsx?|mjs|cjs|java|php|py|rb|go|rs|cs|swift|kt)$/i;
const MARKUP_FILE = /\.(?:html?|vue|svelte)$/i;
const SECRET_FILE = /(?:\.(?:[cm]?js|jsx|tsx?|mjs|cjs|json|ya?ml|toml|ini|conf|config)$|(?:^|\/)(?:\.env(?:\..*)?|\.npmrc|\.pypirc|id_rsa|credentials(?:\.[\w-]+)?|secrets?(?:\.[\w-]+)?))$/i;
const MARKUP_RULES = new Set(['unsafe-external-links', 'image-alt-text']);
const emit = issue => process.stdout.write(`${JSON.stringify({ type: 'issue', issue })}\n`);

function inspect(ruleName, lines) {
  switch (ruleName) {
    case 'debug-code': return findDebugCode(lines);
    case 'todo-debt': return findTodoDebt(lines);
    case 'duplicate-imports': return findDuplicateImports(lines);
    case 'empty-functions': return findEmptyFunctions(lines);
    case 'magic-values': return findMagicValues(lines);
    case 'long-functions': return findLongFunctions(lines);
    case 'large-files': return findLargeFiles(lines);
    case 'parameter-bloat': return findParameterBloat(lines);
    case 'nested-ternaries': return findNestedTernaries(lines);
    case 'complex-logic': return findComplexLogic(lines);
    case 'logic-conditions': return findLogicConditions(lines);
    case 'non-strict-equality': return findNonStrictEquality(lines);
    case 'missing-switch-default': return findMissingSwitchDefault(lines);
    case 'error-handling': return findEmptyCatchBlocks(lines);
    case 'empty-branches': return findEmptyBranches(lines);
    case 'broad-exception-handling': return findBroadExceptionHandling(lines);
    case 'secrets': return findSecrets(lines);
    case 'weak-cryptography': return findWeakCryptography(lines);
    case 'insecure-randomness': return findInsecureRandomness(lines);
    case 'unvalidated-redirects': return findUnvalidatedRedirects(lines);
    case 'sql-injection': return findSqlInjection(lines);
    case 'path-traversal': return findPathTraversal(lines);
    case 'xss-sinks': return findXssSinks(lines);
    case 'tls-validation': return findDisabledTlsValidation(lines);
    case 'unsafe-deserialization': return findUnsafeDeserialization(lines);
    case 'regex-dos': return findRegexDos(lines);
    case 'insecure-cookies': return findInsecureCookies(lines);
    case 'insecure-http': return findInsecureHttp(lines);
    case 'sensitive-logging': return findSensitiveLogging(lines);
    case 'command-injection': return findCommandInjection(lines);
    case 'unsafe-operations': return findUnsafeOperations(lines);
    case 'unbounded-loops': return findUnboundedLoops(lines);
    case 'deprecated-apis': return findDeprecatedApis(lines);
    case 'unsafe-external-links': return findUnsafeExternalLinks(lines);
    case 'image-alt-text': return findMissingImageAltText(lines);
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

function findDuplicateImports(lines) {
  const findings = [];
  const imported = new Map();
  lines.forEach((line, index) => {
    const source = withoutLineComments(line);
    const module = source.match(/\bimport(?:[\s\S]*?\sfrom)?\s*['"]([^'"]+)['"]|\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/)?.slice(1).find(Boolean);
    if (!module) return;
    const previous = imported.get(module);
    if (previous) findings.push({ line: index + 1, symbol: module, reason: `Module ${module} is imported again after line ${previous}. Combine imports to keep dependencies clear.` });
    else imported.set(module, index + 1);
  });
  return findings;
}

function findEmptyFunctions(lines) {
  const findings = [];
  const controls = new Set(['if', 'for', 'while', 'switch', 'catch']);
  for (let index = 0; index < lines.length; index += 1) {
    const source = codeOnly(lines[index]);
    const match = source.match(/(?:\bfunction\s+([\w$]+)|\b([\w$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|\b([\w$]+)\s*\([^)]*\)\s*\{)/);
    if (!match || !source.includes('{')) continue;
    const name = match[1] || match[2] || match[3] || 'function';
    if (controls.has(name) || /^(?:noop|noOp|stub|placeholder)$/i.test(name)) continue;
    const opening = source.indexOf('{');
    const end = closingLine(lines, index, opening);
    if (end === -1) continue;
    const body = (end === index ? lines[index].slice(opening + 1, lines[index].lastIndexOf('}')) : lines.slice(index + 1, end).join('\n')).replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '').trim();
    if (!body) findings.push({ line: index + 1, endLine: end + 1, symbol: name, reason: 'Named function has an empty body. Implement it, remove it, or document why it is an intentional extension point.' });
  }
  return findings;
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

function findLargeFiles(lines) {
  return lines.length > 900 ? [{ line: 1, endLine: lines.length, symbol: `${lines.length} lines`, reason: `Source file contains ${lines.length} lines. Split it by responsibility to make review, testing, and AI-assisted changes safer.` }] : [];
}

function findParameterBloat(lines) {
  return lines.flatMap((line, index) => {
    const match = codeOnly(line).match(/(?:\bfunction\s+([\w$]+)|\b([\w$]+)\s*=\s*(?:async\s*)?)\s*\(([^)]*)\)\s*(?:=>|\{)/);
    if (!match) return [];
    const parameters = match[3].split(',').map(value => value.trim()).filter(Boolean);
    if (parameters.length <= 6) return [];
    return [{ line: index + 1, symbol: match[1] || match[2], reason: `Function accepts ${parameters.length} parameters. Group related inputs into an options object or extract a focused collaborator.` }];
  });
}

function findNestedTernaries(lines) {
  return lines.flatMap((line, index) => {
    const ternaries = (codeOnly(line).match(/\?(?!\.)/g) || []).length;
    return ternaries > 1 ? [{ line: index + 1, symbol: '?:', reason: 'Nested ternary expressions are difficult to review and modify. Use a named condition or an explicit branch.' }] : [];
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

function findNonStrictEquality(lines) {
  return lines.flatMap((line, index) => {
    const source = codeOnly(line);
    if (!/(?:^|[^=!])==(?!=)|!=(?!=)/.test(source)) return [];
    if (/(?:==|!=)\s*null\b|\bnull\s*(?:==|!=)/.test(source)) return [];
    return [{ line: index + 1, reason: 'Non-strict equality can coerce values unexpectedly. Use === or !== unless coercion is explicitly required.' }];
  });
}

function findMissingSwitchDefault(lines) {
  const findings = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!/\bswitch\s*\(/.test(codeOnly(lines[index])) || !lines[index].includes('{')) continue;
    const end = closingLine(lines, index, lines[index].indexOf('{'));
    if (end === -1) continue;
    const body = lines.slice(index, end + 1).join('\n');
    const cases = (body.match(/\bcase\b/g) || []).length;
    if (cases >= 2 && !/\bdefault\s*:/.test(body)) findings.push({ line: index + 1, endLine: end + 1, symbol: 'switch', reason: 'Switch handles multiple cases without a default path. Add an explicit fallback for future or unexpected values.' });
  }
  return findings;
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

function findEmptyBranches(lines) {
  const findings = [];
  for (let index = 0; index < lines.length; index += 1) {
    const source = codeOnly(lines[index]);
    if (!/\b(?:if|else\s+if|else)\b[^{}]*\{/.test(source)) continue;
    const opening = source.indexOf('{');
    const end = closingLine(lines, index, opening);
    if (end === -1) continue;
    const body = (end === index ? lines[index].slice(opening + 1, lines[index].lastIndexOf('}')) : lines.slice(index + 1, end).join('\n')).replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '').trim();
    if (!body) findings.push({ line: index + 1, endLine: end + 1, reason: 'Conditional branch is empty. Remove the branch or make the intentional no-op explicit.' });
  }
  return findings;
}

function findBroadExceptionHandling(lines) {
  return lines.flatMap((line, index) => {
    const source = codeOnly(line);
    const match = source.match(/\bcatch\s*\(\s*(?:Exception|Throwable|Error|BaseException)\b[^)]*\)|^\s*except\s*(?:Exception|BaseException)\s*:/);
    return match ? [{ line: index + 1, symbol: match[0].trim(), reason: 'Broad exception handling can hide unrelated failures. Catch the narrowest expected error type and preserve unexpected failures.' }] : [];
  });
}

function findInsecureHttp(lines) {
  return lines.flatMap((line, index) => {
    const source = /^\s*\/\//.test(line) ? '' : line;
    const urls = [...source.matchAll(/['"](http:\/\/[^'"\s/]+[^'"]*)['"]/gi)].map(match => match[1]);
    const unsafe = urls.find(url => !/^http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::|\/|$)/i.test(url));
    return unsafe ? [{ line: index + 1, symbol: 'http://', reason: 'Non-local endpoint uses unencrypted HTTP. Use HTTPS unless the transport is deliberately isolated and protected.' }] : [];
  });
}

function findSensitiveLogging(lines) {
  return lines.flatMap((line, index) => {
    const source = codeOnly(line);
    if (!/\b(?:console\.(?:log|debug|info)|logger\.(?:debug|info)|print)\s*\(/i.test(source)) return [];
    if (!/(?:password|passwd|token|secret|api[_-]?key|credential|authorization|cookie)/i.test(source)) return [];
    return [{ line: index + 1, symbol: 'log', reason: 'Logging appears to include a sensitive value. Redact it or log a non-sensitive identifier instead.' }];
  });
}

function findCommandInjection(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (!/\b(?:exec|execSync|spawn|spawnSync|system|shell_exec|passthru)\s*\(/.test(source)) return [];
    if (!/\b(?:req|request)\.(?:query|params|body)|\b(?:userInput|commandInput|input)\b/i.test(source)) return [];
    return [{ line: index + 1, symbol: 'command', reason: 'Shell command construction appears to receive request or user-controlled input. Use an allowlist and pass fixed arguments without a shell.' }];
  });
}

function findUnboundedLoops(lines) {
  const findings = [];
  for (let index = 0; index < lines.length; index += 1) {
    const source = codeOnly(lines[index]);
    if (!/\bwhile\s*\(\s*true\s*\)|\bfor\s*\(\s*;\s*;\s*\)|^\s*loop\s*\{/.test(source)) continue;
    const opening = source.indexOf('{');
    const end = opening === -1 ? -1 : closingLine(lines, index, opening);
    const body = end === -1 ? lines.slice(index, Math.min(index + 12, lines.length)).join('\n') : lines.slice(index, end + 1).join('\n');
    if (/\bbreak\b|\breturn\b|\bthrow\b/.test(body)) continue;
    findings.push({ line: index + 1, endLine: end === -1 ? index + 1 : end + 1, reason: 'Loop has no detected exit path. Add a bounded condition, cancellation path, or explicit break to prevent runaway work.' });
  }
  return findings;
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

function findWeakCryptography(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    const algorithm = source.match(/\b(?:createHash|MessageDigest\.getInstance|hash(?:lib)?\.(?:new|md5|sha1))\s*\(?\s*['"]?(md5|sha-?1)\b/i)
      || source.match(/\b(?:createCipher|createDecipher|Cipher\.getInstance)\s*\(?\s*['"]?((?:des|rc4|rc2)\b[^'"]*)/i);
    if (!algorithm) return [];
    return [{ line: index + 1, symbol: algorithm[1], reason: `${algorithm[1].toUpperCase()} is a legacy cryptographic algorithm. Use a modern, supported algorithm such as SHA-256 or AES-GCM.` }];
  });
}

function findInsecureRandomness(lines) {
  return lines.flatMap((line, index) => {
    if (!/\bMath\.random\s*\(/.test(codeOnly(line))) return [];
    const context = lines.slice(Math.max(0, index - 1), Math.min(lines.length, index + 2)).join(' ');
    if (!/(?:token|session|auth|password|secret|api[_-]?key|nonce|csrf|reset)/i.test(context)) return [];
    return [{ line: index + 1, symbol: 'Math.random', reason: 'Math.random() is predictable for a security-sensitive value. Use crypto.getRandomValues() or a cryptographically secure server-side generator.' }];
  });
}

function findUnvalidatedRedirects(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:res|response)\.redirect\s*\(\s*(?:req|request)\.(?:query|params|body)\b/i.test(source)
      || /\b(?:location(?:\.href)?|window\.location)\s*=\s*(?:req|request)\.(?:query|params)\b/i.test(source)) {
      return [{ line: index + 1, symbol: 'redirect', reason: 'Redirect target comes directly from request input. Validate it against an allowlist to prevent open redirects.' }];
    }
    return [];
  });
}

function findDeprecatedApis(lines) {
  return lines.flatMap((line, index) => {
    const code = codeOnly(line);
    if (/\bnew\s+Buffer\s*\(|(?<![\w$.])Buffer\s*\(/.test(code)) return [{ line: index + 1, symbol: 'Buffer', reason: 'Legacy Buffer construction is unsafe. Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe() explicitly.' }];
    if (/\.(?:substr)\s*\(/.test(code)) return [{ line: index + 1, symbol: 'substr', reason: 'String.prototype.substr() is legacy. Use slice() or substring() for clearer, supported behavior.' }];
    if (/(?<![\w$.])(?:escape|unescape)\s*\(/.test(code)) return [{ line: index + 1, symbol: 'escape', reason: 'The global escape/unescape APIs are deprecated. Use encodeURIComponent/decodeURIComponent or a purpose-built encoder.' }];
    if (/\bfs\.exists\s*\(/.test(code)) return [{ line: index + 1, symbol: 'fs.exists', reason: 'fs.exists() is deprecated. Use fs.access(), fs.existsSync(), or fs.promises.access() as appropriate.' }];
    return [];
  });
}

function findSqlInjection(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:query|execute|raw)\s*\(\s*`[^`]*\$\{\s*(?:req|request)\./i.test(source)
      || /\b(?:query|execute|raw)\s*\(\s*['"][^'"]*['"]\s*\+\s*(?:req|request)\./i.test(source)) {
      return [{ line: index + 1, symbol: 'query', reason: 'Database query includes request input through string construction. Use parameterized queries or prepared statements.' }];
    }
    return [];
  });
}

function findPathTraversal(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:path\.)?(?:join|resolve)\s*\([^)]*(?:req|request)\.(?:params|query|body)\b/i.test(source)) {
      return [{ line: index + 1, symbol: 'path.join', reason: 'Filesystem path includes request input directly. Normalize it and enforce that the resolved path remains inside an allowed root.' }];
    }
    return [];
  });
}

function findXssSinks(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:innerHTML|outerHTML)\s*=\s*(?:req|request)\.(?:query|params|body)\b/i.test(source)
      || /\b(?:document\.write|insertAdjacentHTML)\s*\([^)]*(?:req|request)\.(?:query|params|body)\b/i.test(source)) {
      return [{ line: index + 1, symbol: 'HTML sink', reason: 'Untrusted request input reaches an HTML sink. Sanitize it or render it as text to prevent cross-site scripting.' }];
    }
    return [];
  });
}

function findDisabledTlsValidation(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b|\bverify\s*=\s*False\b/.test(source)) {
      return [{ line: index + 1, symbol: 'TLS validation', reason: 'TLS certificate validation is disabled. Re-enable validation and trust only the required certificate authority.' }];
    }
    return [];
  });
}

function findUnsafeDeserialization(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:yaml|jsyaml)\.load\s*\(|\bunserialize\s*\(|\bpickle\.loads\s*\(/i.test(source)) {
      return [{ line: index + 1, symbol: 'deserialization', reason: 'Potentially unsafe deserialization can construct unexpected objects. Use a safe loader or validate data against a strict schema.' }];
    }
    return [];
  });
}

function findRegexDos(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:new\s+)?RegExp\s*\(\s*(?:req|request)\.(?:query|params|body)\b/i.test(source)
      || /\([^)]*[+*][^)]*\)[+*]/.test(source)) {
      return [{ line: index + 1, symbol: 'RegExp', reason: 'Regular expression may allow catastrophic backtracking or untrusted pattern input. Bound the input and simplify nested quantifiers.' }];
    }
    return [];
  });
}

function findInsecureCookies(lines) {
  return lines.flatMap((line, index) => {
    const source = withoutLineComments(line);
    if (/\b(?:res|response)\.cookie\s*\(\s*['"](?:session|auth|token|jwt)[^'"]*['"]\s*,\s*[^,)]*\)/i.test(source)) {
      return [{ line: index + 1, symbol: 'cookie', reason: 'Sensitive cookie is set without explicit security options. Set httpOnly, secure, and an appropriate sameSite policy.' }];
    }
    return [];
  });
}

function findUnsafeExternalLinks(lines) {
  return lines.flatMap((line, index) => {
    const source = line;
    if (/<a\b[^>]*\btarget\s*=\s*['"]_blank['"][^>]*>/i.test(source) && !/\brel\s*=\s*['"][^'"]*\bnoopener\b/i.test(source)) {
      return [{ line: index + 1, symbol: 'target=_blank', reason: 'External link opens a new tab without rel="noopener". Add noopener (and usually noreferrer) to prevent tabnabbing.' }];
    }
    return [];
  });
}

function findMissingImageAltText(lines) {
  return lines.flatMap((line, index) => {
    const source = line;
    if (/<img\b[^>]*>/i.test(source) && !/\balt\s*=/.test(source)) {
      return [{ line: index + 1, symbol: 'img', reason: 'Image is missing alt text. Add meaningful alt text, or alt="" when the image is purely decorative.' }];
    }
    return [];
  });
}

function withoutLineComments(line) { return line.replace(/\/\/.*$/, '').replace(/\/\*[\s\S]*?\*\//g, ''); }

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
  if (!(SOURCE_FILE.test(file) || (rule === 'secrets' && SECRET_FILE.test(file)) || (MARKUP_RULES.has(rule) && MARKUP_FILE.test(file)))) continue;
  try {
    const text = await fs.readFile(path.join(root, file), 'utf8');
    const lines = text.split(/\r?\n/);
    for (const issue of inspect(rule, lines)) emit({ file, ...issue });
  } catch {
    // Skip files that cannot be decoded as source text.
  }
}
