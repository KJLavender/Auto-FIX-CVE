/** Rewrites `key = "spec"` and `key = { version = "spec", ... }` lines for every matching key. */
export function rewriteTableEntries(text: string, keys: string[], next: (old: string) => string): string {
  for (const key of keys) {
    const quoted = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    text = text.replace(new RegExp(`^(\\s*"?${quoted}"?\\s*=\\s*)"([^"]*)"`, "gm"), (_m, lead: string, old: string) => `${lead}"${next(old)}"`);
    text = text.replace(
      new RegExp(`^(\\s*"?${quoted}"?\\s*=\\s*\\{[^}\\n]*version\\s*=\\s*)"([^"]*)"`, "gm"),
      (_m, lead: string, old: string) => `${lead}"${next(old)}"`,
    );
  }
  return text;
}
