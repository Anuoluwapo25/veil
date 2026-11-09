import { test } from "node:test";
import assert from "node:assert/strict";
import { redact, restore } from "../src/redact.ts";

const SAMPLE = `Refund Ada (ada.obi@gmail.com, 08031234567).
Her BVN is 22123456789. Email ada.obi@gmail.com once done.`;

test("removes every sensitive value from the text", () => {
  const { text } = redact(SAMPLE);
  for (const v of ["ada.obi@gmail.com", "08031234567", "22123456789"]) {
    assert.ok(!text.includes(v), `${v} leaked`);
  }
  assert.match(text, /«EMAIL_1».*«NG_PHONE_1».*«NG_BVN_1»/s);
});

test("the same value always gets the same placeholder", () => {
  const { text } = redact(SAMPLE);
  assert.equal(text.match(/«EMAIL_1»/g)?.length, 2);
  assert.ok(!text.includes("«EMAIL_2»"));
});

test("restore gives back the exact original", () => {
  const { text, vault } = redact(SAMPLE);
  assert.equal(restore(text, vault), SAMPLE);
});

test("restores placeholders inside an agent's reply", () => {
  const { vault } = redact(SAMPLE);
  const reply = "I've queued the refund and will email «EMAIL_1».";
  assert.equal(restore(reply, vault), "I've queued the refund and will email ada.obi@gmail.com.");
});

test("an existing vault keeps numbering stable across redactions", () => {
  const first = redact("contact a@gmail.com");
  const second = redact("contact b@gmail.com or a@gmail.com", first.vault);
  assert.equal(second.text, "contact «EMAIL_2» or «EMAIL_1»");
});

test("unknown placeholders are left alone", () => {
  assert.equal(restore("see «EMAIL_9»", {}), "see «EMAIL_9»");
});

test("text with nothing sensitive passes through unchanged", () => {
  const { text, findings } = redact("just code");
  assert.equal(text, "just code");
  assert.equal(findings.length, 0);
});
