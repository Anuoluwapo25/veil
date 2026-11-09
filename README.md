# Veil

**Your agents see everything in your repo. Veil makes sure your secrets and your users' data never leave with them.**

AI coding agents read `.env` files, logs, support tickets and database dumps, then send that text to a model provider. Veil finds secrets and personal data first and swaps them for placeholders such as `«NG_BVN_1»`. The agent still works with the text, the provider never sees the real values, and Veil restores them in the agent's reply.

General PII tools don't know African identifiers. Veil detects Nigerian **BVN**, **NIN**, mobile numbers and **NUBAN bank accounts** (checked against the CBN check-digit algorithm), alongside API keys for Paystack, Flutterwave, Stripe, OpenAI, Anthropic, GitHub and AWS.

## Try it

Requires Node 22.18+. No runtime dependencies.

```bash
npm install
node src/cli.ts scan examples/support-ticket.txt
node src/cli.ts redact examples/support-ticket.txt --map session.veilmap.json > redacted.txt
node src/cli.ts restore redacted.txt --map session.veilmap.json
```

```
2:20  email            high  ad************om  email address
2:46  ng_phone         high  +2************67  Nigerian mobile number
3:6   ng_bvn           high  22*******89       11-digit number labelled as a BVN
4:18  ng_bank_account  high  01******85        valid NUBAN check digit for GTBank
5:20  assigned_secret  high  co************ry  value assigned to a secret-looking name
```

- `scan` never prints a full value and exits 1 when it finds something, so it works as a hook or CI gate.
- `redact` writes the originals to a vault file readable only by you (mode 600). Keep it out of git.
- The same value always gets the same placeholder, so the agent can still tell two mentions are one person.

## How detection works

| Kind | How it's recognised |
|---|---|
| API keys, tokens, private keys | Provider-specific formats, plus literal values assigned to names like `password` or `api_key` (references such as `process.env.X` are ignored) |
| BVN / NIN | 11-digit numbers labelled as such; unlabelled numbers starting with `22` are reported as medium-confidence BVNs |
| NUBAN | 10-digit numbers labelled as accounts or next to a bank name; high confidence when the check digit is valid for that bank |
| Phone | Nigerian mobile prefixes (070, 080, 081, 090, 091) in local and +234 formats |
| Cards | 13–19 digits that pass the Luhn check |
| Email | Any address except RFC 2606 example domains |

## Develop

```bash
npm run check   # typecheck + tests
```

## Roadmap

- Sit between a coding agent and its model provider, redacting automatically
- Audit log of what each agent session tried to send
- PR check that flags personal data flowing into logs, analytics or third-party APIs
- NDPA 2023 (Nigeria Data Protection Act) mapping for each finding
