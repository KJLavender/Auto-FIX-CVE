import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import ts from "typescript";
import type { Usage } from "../types.js";

const SOURCE_EXT = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "coverage", ".git", ".next", "out"]);

interface Binding {
  local: string;
  /** Exported name, `default`, or `*` for namespace / CommonJS module objects. */
  imported: string;
  specifier: string;
}

export async function listSourceFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith(".")) {
        out.push(...(await listSourceFiles(path.join(dir, entry.name))));
      }
    } else if (SOURCE_EXT.has(path.extname(entry.name)) && !entry.name.endsWith(".d.ts")) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

function matchesPackage(specifier: string, pkg: string): boolean {
  return specifier === pkg || specifier.startsWith(pkg + "/");
}

function scriptKind(file: string): ts.ScriptKind {
  switch (path.extname(file)) {
    case ".tsx":
      return ts.ScriptKind.TSX;
    case ".jsx":
      return ts.ScriptKind.JSX;
    case ".js":
    case ".mjs":
    case ".cjs":
      return ts.ScriptKind.JS;
    default:
      return ts.ScriptKind.TS;
  }
}

function isRequireOf(node: ts.Node, pkg: string): node is ts.CallExpression {
  return (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "require" &&
    node.arguments.length === 1 &&
    ts.isStringLiteralLike(node.arguments[0]) &&
    matchesPackage(node.arguments[0].text, pkg)
  );
}

/**
 * Finds every place `source` uses one of `packages`. Scoping is ignored: an
 * identifier that shadows an import is still reported, which errs on the side
 * of showing too much rather than missing a vulnerable call.
 */
export function findUsagesInSource(file: string, source: string, packages: string[]): Map<string, Usage[]> {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, scriptKind(file));
  const lines = source.split(/\r?\n/);
  const result = new Map<string, Usage[]>();

  const record = (pkg: string, node: ts.Node, specifier: string, symbol: string) => {
    const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    const list = result.get(pkg) ?? [];
    list.push({
      file,
      line: line + 1,
      column: character + 1,
      specifier,
      symbol,
      snippet: lines[line].trim(),
      mentionedBy: [],
    });
    result.set(pkg, list);
  };

  for (const pkg of packages) {
    const bindings = new Map<string, Binding>();
    const declarations = new Set<ts.Node>();

    // Pass 1: collect how the package is brought into scope.
    const collect = (node: ts.Node): void => {
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier) &&
        matchesPackage(node.moduleSpecifier.text, pkg)
      ) {
        const specifier = node.moduleSpecifier.text;
        // Type-only imports and re-exports are erased at compile time: they never load the package.
        if ((ts.isImportDeclaration(node) && node.importClause?.isTypeOnly) || (ts.isExportDeclaration(node) && node.isTypeOnly)) {
          return;
        }
        const clause = ts.isImportDeclaration(node) ? node.importClause : undefined;
        if (!clause) {
          record(pkg, node, specifier, ts.isExportDeclaration(node) ? "(re-export)" : "(side-effect import)");
          return;
        }
        if (clause.name) {
          bindings.set(clause.name.text, { local: clause.name.text, imported: "default", specifier });
        }
        const named = clause.namedBindings;
        if (named && ts.isNamespaceImport(named)) {
          bindings.set(named.name.text, { local: named.name.text, imported: "*", specifier });
        } else if (named) {
          for (const el of named.elements) {
            if (el.isTypeOnly) continue;
            bindings.set(el.name.text, { local: el.name.text, imported: (el.propertyName ?? el.name).text, specifier });
          }
        }
        declarations.add(node);
        return;
      }

      // TypeScript's CommonJS form: `import x = require("pkg")`.
      if (
        ts.isImportEqualsDeclaration(node) &&
        !node.isTypeOnly &&
        ts.isExternalModuleReference(node.moduleReference) &&
        ts.isStringLiteral(node.moduleReference.expression) &&
        matchesPackage(node.moduleReference.expression.text, pkg)
      ) {
        bindings.set(node.name.text, { local: node.name.text, imported: "*", specifier: node.moduleReference.expression.text });
        declarations.add(node);
        return;
      }

      if (isRequireOf(node, pkg)) {
        const specifier = (node.arguments[0] as ts.StringLiteral).text;
        const parent = node.parent;
        if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
          bindings.set(parent.name.text, { local: parent.name.text, imported: "*", specifier });
          declarations.add(parent.name);
        } else if (ts.isVariableDeclaration(parent) && ts.isObjectBindingPattern(parent.name)) {
          for (const el of parent.name.elements) {
            if (!ts.isIdentifier(el.name)) continue;
            const imported = el.propertyName && ts.isIdentifier(el.propertyName) ? el.propertyName.text : el.name.text;
            bindings.set(el.name.text, { local: el.name.text, imported, specifier });
          }
          declarations.add(parent.name);
        } else if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
          record(pkg, parent, specifier, parent.name.text);
        } else {
          record(pkg, node, specifier, "(require)");
        }
      }

      if (
        ts.isCallExpression(node) &&
        node.expression.kind === ts.SyntaxKind.ImportKeyword &&
        node.arguments.length === 1 &&
        ts.isStringLiteralLike(node.arguments[0]) &&
        matchesPackage(node.arguments[0].text, pkg)
      ) {
        record(pkg, node, node.arguments[0].text, "(dynamic import)");
      }

      ts.forEachChild(node, collect);
    };
    collect(sf);
    if (bindings.size === 0) continue;

    // Pass 2: find references to the collected bindings.
    const visit = (node: ts.Node): void => {
      if (declarations.has(node)) return;
      if (ts.isIdentifier(node)) {
        const b = bindings.get(node.text);
        const parent = node.parent;
        const isPropertyName =
          (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
          (ts.isPropertyAssignment(parent) && parent.name === node);
        if (b && !isPropertyName) {
          let symbol = b.imported;
          if ((b.imported === "*" || b.imported === "default") && ts.isPropertyAccessExpression(parent)) {
            symbol = parent.name.text;
          } else if ((b.imported === "*" || b.imported === "default") && ts.isCallExpression(parent) && parent.expression === node) {
            symbol = b.imported === "*" ? "(module called as function)" : "default()";
          }
          record(pkg, node, b.specifier, symbol);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return result;
}

export async function findUsages(projectDir: string, packages: string[]): Promise<Map<string, Usage[]>> {
  const merged = new Map<string, Usage[]>();
  if (packages.length === 0) return merged;
  for (const file of await listSourceFiles(projectDir)) {
    const source = await readFile(file, "utf8");
    // Only analyse the packages this file can mention: each one costs a full AST walk.
    const present = packages.filter((p) => source.includes(p));
    if (present.length === 0) continue;
    const rel = path.relative(projectDir, file).split(path.sep).join("/");
    for (const [pkg, usages] of findUsagesInSource(rel, source, present)) {
      merged.set(pkg, [...(merged.get(pkg) ?? []), ...usages]);
    }
  }
  return merged;
}
