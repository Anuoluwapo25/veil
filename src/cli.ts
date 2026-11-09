#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { parseArgs } from "node:util";
import { scan, type Finding } from "./detectors.ts";
import { redact, restore, type Vault } from "./redact.ts";

const USAGE = `veil: keep secrets and personal data away from AI agents

Usage:
  veil scan    [file]              List secrets and personal data (exit 1 if any found)
  veil redact  [file] --map <path> Print the text with placeholders; save originals to <path>
  veil restore [file] --map <path> Put the originals from <path> back into the text

Reads stdin when no file is given.

Options:
  --map <path>  Vault file holding placeholder → original value (keep it local)
  --json        (scan) Output findings as JSON
  -h, --help    Show this help`;

/** Show enough to recognise a value without revealing it. */
function mask(value: string): string {
  const v = value.replace(/\s+/g, " ");
  if (v.length <= 6) return "*".repeat(v.length);
  return `${v.slice(0, 2)}${"*".repeat(Math.min(v.length - 4, 12))}${v.slice(-2)}`;
}

function lineCol(text: string, index: number): string {
  const before = text.slice(0, index);
  const line = before.split("\n").length;
  const col = index - before.lastIndexOf("\n");
  return `${line}:${col}`;
}

function formatFindings(text: string, findings: Finding[]): string {
  if (findings.length === 0) return "No secrets or personal data found.";
  const rows = findings.map((f) => [
    lineCol(text, f.start),
    f.type,
    f.confidence,
    mask(f.value),
    f.reason,
  ]);
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  const lines = rows.map((r) => r.map((c, i) => c.padEnd(widths[i])).join("  ").trimEnd());
  const secrets = findings.filter((f) => f.category === "secret").length;
  return `${lines.join("\n")}\n\n${findings.length} found (${secrets} secret, ${findings.length - secrets} personal data)`;
}

function main(argv: string[]): number {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      map: { type: "string" },
      json: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [command, file] = positionals;
  if (values.help || !command) {
    console.log(USAGE);
    return command || values.help ? 0 : 2;
  }

  const input = readFileSync(file ?? 0, "utf8");

  switch (command) {
    case "scan": {
      const findings = scan(input);
      if (values.json) {
        const safe = findings.map(({ value, ...f }) => ({ ...f, preview: mask(value) }));
        console.log(JSON.stringify(safe, null, 2));
      } else {
        console.log(formatFindings(input, findings));
      }
      return findings.length > 0 ? 1 : 0;
    }
    case "redact": {
      if (!values.map) {
        console.error("veil redact needs --map <path> so the originals can be restored later.");
        return 2;
      }
      const vault: Vault = existsSync(values.map) ? JSON.parse(readFileSync(values.map, "utf8")) : {};
      const result = redact(input, vault);
      writeFileSync(values.map, JSON.stringify(result.vault, null, 2) + "\n", { mode: 0o600 });
      process.stdout.write(result.text);
      console.error(`veil: replaced ${result.findings.length} value(s); originals saved to ${values.map}`);
      return 0;
    }
    case "restore": {
      if (!values.map) {
        console.error("veil restore needs --map <path>.");
        return 2;
      }
      const vault: Vault = JSON.parse(readFileSync(values.map, "utf8"));
      process.stdout.write(restore(input, vault));
      return 0;
    }
    default:
      console.error(`Unknown command "${command}".\n\n${USAGE}`);
      return 2;
  }
}

process.exitCode = main(process.argv.slice(2));
