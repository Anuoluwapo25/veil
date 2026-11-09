import { findBank, isValidNuban } from "./nuban.ts";

export type Category = "secret" | "pii";
export type Confidence = "high" | "medium";

export interface Finding {
  type: string;
  category: Category;
  confidence: Confidence;
  reason: string;
  value: string;
  start: number;
  end: number;
}

type Hit = Omit<Finding, "type" | "category" | "value">;

export interface Detector {
  type: string;
  category: Category;
  find(text: string): Hit[];
}

/** Characters on either side of a number that we read for context words. */
const CONTEXT_WINDOW = 40;

function regexDetector(
  type: string,
  category: Category,
  regex: RegExp,
  reason: string,
  opts: {
    /** Named capture group to report instead of the whole match. */
    group?: string;
    /** Reject matches that only look like the real thing. */
    accept?: (value: string) => boolean;
  } = {},
): Detector {
  const flags = new Set(regex.flags + "gd");
  const re = new RegExp(regex.source, [...flags].join(""));
  return {
    type,
    category,
    find(text) {
      const hits: Hit[] = [];
      for (const m of text.matchAll(re)) {
        const [start, end] = opts.group
          ? m.indices!.groups![opts.group]!
          : m.indices![0];
        const value = text.slice(start, end);
        if (opts.accept && !opts.accept(value)) continue;
        hits.push({ start, end, confidence: "high", reason });
      }
      return hits;
    },
  };
}

/** Lowercased text around [start, end), on the same line. */
function contextAround(text: string, start: number, end: number): string {
  const lineStart = text.lastIndexOf("\n", start - 1) + 1;
  const nl = text.indexOf("\n", end);
  const lineEnd = nl === -1 ? text.length : nl;
  return text
    .slice(Math.max(lineStart, start - CONTEXT_WINDOW), Math.min(lineEnd, end + CONTEXT_WINDOW))
    .toLowerCase();
}

/** `word` appears in `ctx` with no letters directly around it (so "nin" ≠ "running"). */
function hasWord(ctx: string, word: string): boolean {
  return new RegExp(`(^|[^a-z])${word}([^a-z]|$)`).test(ctx);
}

/**
 * 11-digit Nigerian identity numbers. BVN and NIN are both 11 digits with no
 * public checksum, so we tell them apart (and from order IDs) by context.
 */
function identityDetector(
  type: string,
  words: string[],
  label: string,
  /** Prefix that alone makes a match likely, e.g. BVNs start with 22. */
  likelyPrefix?: string,
): Detector {
  return {
    type,
    category: "pii",
    find(text) {
      const hits: Hit[] = [];
      for (const m of text.matchAll(/(?<!\d|\d\.)\d{11}(?!\d|\.\d)/g)) {
        const start = m.index;
        const end = start + 11;
        const ctx = contextAround(text, start, end);
        if (words.some((w) => hasWord(ctx, w))) {
          hits.push({ start, end, confidence: "high", reason: `11-digit number labelled as ${label}` });
        } else if (likelyPrefix && m[0].startsWith(likelyPrefix)) {
          hits.push({
            start,
            end,
            confidence: "medium",
            reason: `11-digit number starting with ${likelyPrefix}, the usual ${label} prefix`,
          });
        }
      }
      return hits;
    },
  };
}

const nubanDetector: Detector = {
  type: "ng_bank_account",
  category: "pii",
  find(text) {
    const hits: Hit[] = [];
    const words = ["account", "acct", "acc", "a/c", "nuban", "account_number", "accountnumber"];
    for (const m of text.matchAll(/(?<!\d|\d\.)\d{10}(?!\d|\.\d)/g)) {
      const start = m.index;
      const end = start + 10;
      const ctx = contextAround(text, start, end);
      const bank = findBank(ctx);
      const labelled = words.some((w) => ctx.includes(w));
      if (bank && isValidNuban(m[0], bank.code)) {
        hits.push({ start, end, confidence: "high", reason: `valid NUBAN check digit for ${bank.name}` });
      } else if (labelled || bank) {
        hits.push({
          start,
          end,
          confidence: "medium",
          reason: bank
            ? `10-digit number next to ${bank.name}, but the NUBAN check digit doesn't match`
            : "10-digit number labelled as a bank account",
        });
      }
    }
    return hits;
  },
};

/** Luhn checksum, used by every major card scheme. */
function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** RFC 2606 domains reserved for documentation; never real people. */
const EXAMPLE_EMAIL = /@(example\.(com|org|net)|[a-z0-9-]+\.(test|example|invalid))$/i;

/** Assignment values that are references, not secrets: env lookups, templates, placeholders. */
function isLiteralSecret(value: string): boolean {
  return !/^(process\.env|os\.environ|\$\{|\$[A-Z_]|<|«|\*{3,}|x{6,})/i.test(value);
}

/**
 * Ordered by priority: when two detectors claim overlapping text, the one
 * listed first wins. Specific formats come before generic ones.
 */
export const DETECTORS: Detector[] = [
  regexDetector(
    "private_key",
    "secret",
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/,
    "PEM private key block",
  ),
  regexDetector("paystack_secret_key", "secret", /\bsk_(?:live|test)_[0-9a-f]{40}\b/, "Paystack secret key"),
  regexDetector(
    "flutterwave_secret_key",
    "secret",
    /\bFLWSECK(?:_TEST)?-[0-9a-f]{32}-X\b/,
    "Flutterwave secret key",
  ),
  regexDetector("stripe_secret_key", "secret", /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b/, "Stripe secret key"),
  regexDetector("anthropic_api_key", "secret", /\bsk-ant-[A-Za-z0-9_-]{20,}/, "Anthropic API key"),
  regexDetector("openai_api_key", "secret", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/, "OpenAI API key"),
  regexDetector(
    "github_token",
    "secret",
    /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/,
    "GitHub token",
  ),
  regexDetector("aws_access_key_id", "secret", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, "AWS access key ID"),
  regexDetector(
    "jwt",
    "secret",
    /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    "JSON Web Token",
  ),
  regexDetector(
    "assigned_secret",
    "secret",
    /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']?(?<value>[^\s"'`,;]{8,})/i,
    "value assigned to a secret-looking name",
    { group: "value", accept: isLiteralSecret },
  ),
  identityDetector("ng_bvn", ["bvn", "bank verification"], "a BVN", "22"),
  identityDetector("ng_nin", ["nin", "nimc", "national identification", "national id"], "a NIN"),
  nubanDetector,
  regexDetector(
    "ng_phone",
    "pii",
    /(?<![\d+])(?:\+234[\s-]?|234|0)(?:70|80|81|90|91)\d[\s-]?\d{3}[\s-]?\d{4}(?!\d)/,
    "Nigerian mobile number",
  ),
  regexDetector(
    "payment_card",
    "pii",
    /(?<!\d)[2-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?!\d)/,
    "card number that passes the Luhn check",
    {
      accept: (v) => {
        const digits = v.replace(/\D/g, "");
        return digits.length >= 13 && digits.length <= 19 && luhn(digits);
      },
    },
  ),
  regexDetector(
    "email",
    "pii",
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
    "email address",
    { accept: (v) => !EXAMPLE_EMAIL.test(v) },
  ),
];

/** Every finding in `text`, sorted by position, with overlaps resolved by detector priority. */
export function scan(text: string, detectors: Detector[] = DETECTORS): Finding[] {
  const accepted: Finding[] = [];
  for (const d of detectors) {
    for (const hit of d.find(text)) {
      if (accepted.some((f) => hit.start < f.end && f.start < hit.end)) continue;
      accepted.push({ ...hit, type: d.type, category: d.category, value: text.slice(hit.start, hit.end) });
    }
  }
  return accepted.sort((a, b) => a.start - b.start);
}
