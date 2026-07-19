const templates = {
  'dead-code': 'Review `{symbol}` in `{file}:{line}`. It appears to be unused: {reason} Remove it only after checking all source, configuration, dynamic imports, and public API references. Keep the change minimal and preserve behavior.',
  'duplicate-code': 'Refactor the duplicate code in `{file}:{line}`. {reason} Extract the smallest safe shared helper, retain existing behavior and tests, and avoid unrelated formatting changes. Relevant code:\n```\n{snippet}\n```',
  whitespace: 'Fix the formatting issue in `{file}:{line}`: {reason} Make only the whitespace change requested and preserve all code semantics.',
  'package-integrity': 'Investigate the dependency `{symbol}` in `{file}:{line}`. {reason} Verify that it is a real, intended package and that the declared name is correct. Remove or replace it only if it is genuinely invalid and update the lockfile only when necessary.'
};
export function buildPrompt(issue) { return (templates[issue.type] || 'Fix this issue in `{file}:{line}`: {reason}').replace(/\{(\w+)\}/g, (_match, key) => String(issue[key] ?? '')); }
