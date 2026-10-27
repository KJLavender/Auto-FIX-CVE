export interface FromLine {
  /** 1-based line of the FROM instruction. */
  line: number;
  /** Image reference as written, e.g. `${REGISTRY}/node:22-slim`. */
  raw: string;
  /** With ARG defaults substituted, e.g. `nexus:8443/library/node`. */
  repository: string;
  tag?: string;
  digest?: string;
  stage?: string;
  /** The last stage is the image that ships; earlier ones only build it. */
  final: boolean;
  /** When the version comes from `ARG NAME=value`, where that value is written, so a fix edits the ARG instead. */
  arg?: { name: string; line: number; value: string };
}

const ARG = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=("[^"]*"|'[^']*'|\S*))?\s*$/i;
const FROM = /^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$/i;
const VAR = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;

/** Reads the FROM lines of a Dockerfile, resolving ARG defaults declared before them. */
export function parseDockerfile(text: string): FromLine[] {
  const args = new Map<string, { line: number; value: string }>();
  const froms: FromLine[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const arg = ARG.exec(lines[i]);
    // Only ARGs before the first FROM are visible to FROM lines.
    if (arg && froms.length === 0) {
      args.set(arg[1], { line: i + 1, value: (arg[2] ?? "").replace(/^["']|["']$/g, "") });
      continue;
    }
    const from = FROM.exec(lines[i]);
    if (!from) continue;
    const raw = from[1];
    let used: string | undefined;
    const resolved = raw.replace(VAR, (_, braced: string, fallback: string | undefined, bare: string) => {
      const name = braced ?? bare;
      used ??= name;
      return args.get(name)?.value || fallback || "";
    });
    const [ref, digest] = resolved.split("@");
    // The tag is after the last colon, unless that colon belongs to a registry port.
    const colon = ref.lastIndexOf(":");
    const hasTag = colon > ref.lastIndexOf("/");
    const tagPart = raw.split("@")[0];
    const usesArgInTag = used !== undefined && tagPart.lastIndexOf(":") > tagPart.lastIndexOf("/") && /\$/.test(tagPart.slice(tagPart.lastIndexOf(":")));
    froms.push({
      line: i + 1,
      raw,
      repository: hasTag ? ref.slice(0, colon) : ref,
      tag: hasTag ? ref.slice(colon + 1) : undefined,
      digest,
      stage: from[2],
      final: false,
      arg: usesArgInTag && used && args.has(used) ? { name: used, ...args.get(used)! } : undefined,
    });
  }
  // The last stage ships, and so does any stage it is built FROM (`FROM base AS app`).
  let shipped = froms.at(-1);
  while (shipped && !shipped.final) {
    shipped.final = true;
    const parent = shipped.repository;
    shipped = froms.find((f) => f.stage === parent && !f.final);
  }
  return froms;
}

/** The image name without registry or namespace: `nexus:8443/library/node` → `node`. */
export function imageName(repository: string): string {
  return repository.split("/").pop() ?? repository;
}
