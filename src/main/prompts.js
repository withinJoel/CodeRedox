const templates = {
  "dead-code":
    "Review `{symbol}` in `{file}:{line}`. It appears to be unused: {reason} Remove it only after checking all source, configuration, dynamic imports, and public API references. Keep the change minimal and preserve behavior.",
  "duplicate-code":
    "Refactor the duplicate code in `{file}:{line}`. {reason} Extract the smallest safe shared helper, retain existing behavior and tests, and avoid unrelated formatting changes. Relevant code:\n```\n{snippet}\n```",
  whitespace:
    "Fix the formatting issue in `{file}:{line}`: {reason} Make only the whitespace change requested and preserve all code semantics.",
  "debug-code":
    "Remove or replace the development-only code in `{file}:{line}`. {reason} Preserve intentional diagnostics by routing them through the project's approved logger; otherwise delete the statement without changing behavior.",
  "todo-debt":
    "Review the maintenance marker in `{file}:{line}`. {reason} Either complete the work, replace it with a precise tracked-work reference, or remove it if it is no longer useful. Keep the change focused.",
  "magic-values":
    "Improve the readability of `{file}:{line}`. {reason} Introduce a well-named constant at the narrowest useful scope, unless the literal is truly self-explanatory. Preserve behavior and avoid unrelated refactors.",
  "long-functions":
    "Refactor `{symbol}` in `{file}:{line}`. {reason} Extract cohesive sections into small helpers with intention-revealing names, keeping the public behavior, error handling, and tests unchanged.",
  "complex-logic":
    "Simplify the control flow in `{symbol}` at `{file}:{line}`. {reason} Prefer guard clauses, named predicates, or small decision helpers while maintaining exact behavior for every branch.",
  "logic-conditions":
    "Correct the condition in `{file}:{line}`. {reason} Confirm the intended boolean behavior with a focused test and make the smallest change that preserves the surrounding control flow.",
  "error-handling":
    "Fix the error handling at `{file}:{line}`. {reason} Handle the expected failure deliberately, add context where useful, and do not silently discard failures unless that is an explicitly documented product decision.",
  "unsafe-operations":
    "Review the dynamic operation in `{file}:{line}`. {reason} Replace it with a safer explicit API where possible; otherwise tightly validate inputs and retain the smallest necessary execution boundary.",
  "package-integrity":
    "Investigate the dependency `{symbol}` in `{file}:{line}`. {reason} Verify that it is a real, intended package and that the declared name is correct. Remove or replace it only if it is genuinely invalid and update the lockfile only when necessary.",
};
export function buildPrompt(issue) {
  return (
    templates[issue.type] || "Fix this issue in `{file}:{line}`: {reason}"
  ).replace(/\{(\w+)\}/g, (_match, key) => String(issue[key] ?? ""));
}
