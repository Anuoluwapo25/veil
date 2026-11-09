import { scan, type Finding } from "./detectors.ts";

/** Placeholder → original value. Never leaves the machine. */
export type Vault = Record<string, string>;

const PLACEHOLDER = /«([A-Z0-9_]+)_(\d+)»/g;

export interface Redaction {
  text: string;
  vault: Vault;
  findings: Finding[];
}

/**
 * Replace every finding with a placeholder like «NG_BVN_1». The same value
 * always gets the same placeholder, so an agent can still tell that two
 * mentions refer to one thing. Pass an existing vault to keep numbering
 * stable across several redactions in one session.
 */
export function redact(text: string, vault: Vault = {}): Redaction {
  const findings = scan(text);
  const byValue = new Map(Object.entries(vault).map(([ph, v]) => [v, ph]));
  const counters = new Map<string, number>();
  for (const ph of Object.keys(vault)) {
    const [, type, n] = /^«([A-Z0-9_]+)_(\d+)»$/.exec(ph) ?? [];
    if (type) counters.set(type, Math.max(counters.get(type) ?? 0, Number(n)));
  }

  let out = "";
  let cursor = 0;
  for (const f of findings) {
    let ph = byValue.get(f.value);
    if (!ph) {
      const type = f.type.toUpperCase();
      const n = (counters.get(type) ?? 0) + 1;
      counters.set(type, n);
      ph = `«${type}_${n}»`;
      vault[ph] = f.value;
      byValue.set(f.value, ph);
    }
    out += text.slice(cursor, f.start) + ph;
    cursor = f.end;
  }
  out += text.slice(cursor);
  return { text: out, vault, findings };
}

/** Put the original values back. Unknown placeholders are left untouched. */
export function restore(text: string, vault: Vault): string {
  return text.replace(PLACEHOLDER, (ph) => vault[ph] ?? ph);
}
