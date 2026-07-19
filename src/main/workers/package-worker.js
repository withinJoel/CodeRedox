import fs from "node:fs/promises";
import path from "node:path";
const root = process.argv[2];
const issues = [];
try {
  const pkgPath = path.join(root, "package.json");
  const text = await fs.readFile(pkgPath, "utf8");
  const pkg = JSON.parse(text);
  for (const [name, version] of Object.entries({
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {}),
  })) {
    if (
      !/^(?:@[-a-z0-9~][a-z0-9~._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name) ||
      /(?:fix|helper|util|manager|core)-(?:ai|gpt|chat|llm)/i.test(name)
    )
      issues.push({
        file: "package.json",
        line:
          text.split(/\r?\n/).findIndex((line) => line.includes(`"${name}"`)) +
            1 || 1,
        symbol: name,
        reason: `Package name or declaration looks suspicious (${version}).`,
      });
  }
} catch {
  /* no package manifest */
}
process.stdout.write(JSON.stringify(issues));
