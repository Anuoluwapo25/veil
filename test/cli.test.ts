import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const CLI = new URL("../src/cli.ts", import.meta.url).pathname;

function veil(args: string[], input: string) {
  const r = spawnSync(process.execPath, [CLI, ...args], { input, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("scan exits 1 and masks what it found", () => {
  const r = veil(["scan"], "BVN: 22123456789\n");
  assert.equal(r.code, 1);
  assert.match(r.out, /1:6\s+ng_bvn\s+high/);
  assert.ok(!r.out.includes("22123456789"), "scan output must not reveal the value");
});

test("scan exits 0 on clean input", () => {
  const r = veil(["scan"], "nothing to see\n");
  assert.equal(r.code, 0);
  assert.match(r.out, /No secrets or personal data found/);
});

test("scan --json gives masked previews, never raw values", () => {
  const r = veil(["scan", "--json"], "mail ada.obi@gmail.com");
  const [f] = JSON.parse(r.out);
  assert.equal(f.type, "email");
  assert.equal(f.value, undefined);
  assert.ok(!f.preview.includes("ada.obi@gmail.com"));
});

test("redact then restore round-trips through a private vault file", () => {
  const map = join(mkdtempSync(join(tmpdir(), "veil-")), "session.veilmap.json");
  const original = "Pay GTBank 0123456785 and text 08031234567\n";

  const red = veil(["redact", "--map", map], original);
  assert.equal(red.code, 0);
  assert.equal(red.out, "Pay GTBank «NG_BANK_ACCOUNT_1» and text «NG_PHONE_1»\n");
  assert.equal(statSync(map).mode & 0o777, 0o600, "vault must be readable only by the owner");
  assert.equal(JSON.parse(readFileSync(map, "utf8"))["«NG_PHONE_1»"], "08031234567");

  const back = veil(["restore", "--map", map], red.out);
  assert.equal(back.out, original);
});

test("redact refuses to run without a vault path", () => {
  const r = veil(["redact"], "a@gmail.com");
  assert.equal(r.code, 2);
  assert.match(r.err, /--map/);
});
