import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { scan } from "../src/detectors.ts";
import { isValidNuban, nubanCheckDigit } from "../src/nuban.ts";

// Fake credentials are assembled from parts so secret scanners don't flag this file.
const PAYSTACK = "sk_" + "live_" + "0123456789abcdef".repeat(2) + "01234567";
const FLUTTERWAVE = "FLWSECK" + "_TEST-" + "abcdef0123456789".repeat(2) + "-X";
const STRIPE = "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc";
const ANTHROPIC = "sk-" + "ant-" + "api03-" + "x".repeat(40);
const GITHUB = "gh" + "p_" + "A1b2C3d4E5".repeat(4);
const AWS = "AKIA" + "IOSFODNN7EXAMPLE";
const JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

function types(text: string) {
  return scan(text).map((f) => f.type);
}

describe("secrets", () => {
  const cases: Array<[string, string]> = [
    ["paystack_secret_key", `PAYSTACK_KEY=${PAYSTACK}`],
    ["flutterwave_secret_key", `const key = "${FLUTTERWAVE}"`],
    ["stripe_secret_key", `stripe(${STRIPE})`],
    ["anthropic_api_key", `ANTHROPIC=${ANTHROPIC}`],
    ["github_token", `token ${GITHUB}`],
    ["aws_access_key_id", `aws ${AWS}`],
    ["jwt", `Authorization: Bearer ${JWT}`],
    ["private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"],
  ];
  for (const [type, text] of cases) {
    test(`finds ${type}`, () => assert.deepEqual(types(text), [type]));
  }

  test("a Paystack key is reported once, not also as Stripe or an assignment", () => {
    assert.deepEqual(types(`secret = "${PAYSTACK}"`), ["paystack_secret_key"]);
  });

  test("finds literal values assigned to secret-looking names", () => {
    const [f] = scan(`DB_PASSWORD="correct-horse-battery"`);
    assert.equal(f.type, "assigned_secret");
    assert.equal(f.value, "correct-horse-battery");
  });

  test("ignores references to secrets that aren't the secret itself", () => {
    assert.deepEqual(types("api_key = process.env.API_KEY"), []);
    assert.deepEqual(types("password: ${DB_PASSWORD}"), []);
    assert.deepEqual(types('token: "********"'), []);
  });
});

describe("Nigerian identity numbers", () => {
  test("a labelled BVN is high confidence", () => {
    const [f] = scan("Customer BVN: 22123456789");
    assert.equal(f.type, "ng_bvn");
    assert.equal(f.confidence, "high");
  });

  test("an unlabelled 11-digit number starting with 22 is a medium-confidence BVN", () => {
    const [f] = scan("ref 22198765432");
    assert.equal(f.type, "ng_bvn");
    assert.equal(f.confidence, "medium");
  });

  test("a labelled NIN is found, in code and prose", () => {
    assert.deepEqual(types('user.nin = "70123456789"'), ["ng_nin"]);
    assert.deepEqual(types("my NIMC number is 70123456789"), ["ng_nin"]);
  });

  test("ignores 11-digit numbers with no identity context", () => {
    assert.deepEqual(types("order 48213377190 shipped"), []);
    assert.deepEqual(types("running total 48213377190"), []); // "nin" inside a word
  });
});

describe("Nigerian bank accounts (NUBAN)", () => {
  test("check digit matches a hand-computed GTBank example", () => {
    // 0*3+5*7+8*3 + 0*3+1*7+2*3+3*3+4*7+5*3+6*3+7*7+8*3 = 215 → (10 - 5) % 10 = 5
    assert.equal(nubanCheckDigit("058", "012345678"), 5);
    assert.ok(isValidNuban("0123456785", "058"));
    assert.ok(!isValidNuban("0123456780", "058"));
  });

  test("a valid NUBAN next to its bank name is high confidence", () => {
    const [f] = scan("Pay into GTBank 0123456785");
    assert.equal(f.type, "ng_bank_account");
    assert.equal(f.confidence, "high");
    assert.match(f.reason, /GTBank/);
  });

  test("a bad check digit is still flagged, at medium confidence", () => {
    const [f] = scan("Pay into GTBank 0123456780");
    assert.equal(f.confidence, "medium");
    assert.match(f.reason, /doesn't match/);
  });

  test("a labelled account number is flagged without a bank name", () => {
    assert.deepEqual(types("acct no: 1234567890"), ["ng_bank_account"]);
  });

  test("ignores 10-digit numbers with no banking context", () => {
    assert.deepEqual(types("unix time 1731157200"), []);
  });
});

describe("contact and payment details", () => {
  test("finds Nigerian mobile numbers in common formats", () => {
    for (const n of ["08031234567", "+234 803 123 4567", "2348031234567", "0909-123-4567"]) {
      assert.deepEqual(types(`call ${n}`), ["ng_phone"], n);
    }
  });

  test("ignores numbers that only resemble phone numbers", () => {
    assert.deepEqual(types("0803123456"), []); // 10 digits
    assert.deepEqual(types("06031234567"), []); // not a mobile prefix
  });

  test("finds card numbers only when the Luhn check passes", () => {
    assert.deepEqual(types("card 4111 1111 1111 1111"), ["payment_card"]);
    assert.deepEqual(types("card 4111 1111 1111 1112"), []);
  });

  test("finds real emails but not reserved example domains", () => {
    assert.deepEqual(types("ada.obi@gmail.com"), ["email"]);
    assert.deepEqual(types("dev@example.com and qa@shop.test"), []);
  });
});

test("reports findings in document order with exact positions", () => {
  const text = "email ada@gmail.com, BVN 22123456789";
  const found = scan(text);
  assert.deepEqual(found.map((f) => f.type), ["email", "ng_bvn"]);
  for (const f of found) assert.equal(text.slice(f.start, f.end), f.value);
});

test("clean code produces no findings", () => {
  const code = `export function add(a: number, b: number) {\n  return a + b; // 2026-11-09\n}\n`;
  assert.deepEqual(scan(code), []);
});

test("numbers at the end of a sentence are still found, decimals are not", () => {
  assert.deepEqual(types("Her BVN is 22123456789."), ["ng_bvn"]);
  assert.deepEqual(types("BVN ratio 22123456789.5"), []);
});
