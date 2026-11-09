/**
 * NUBAN (Nigeria Uniform Bank Account Number) check-digit validation.
 *
 * A NUBAN is a 9-digit serial followed by 1 check digit. The check digit is
 * computed over the bank's 3-digit CBN code followed by the 9-digit serial,
 * using weights 3,7,3,3,7,3,3,7,3,3,7,3, then (10 - sum mod 10) mod 10.
 * Source: CBN "Standards on Nigeria Uniform Bank Account Number (NUBAN)".
 */

const WEIGHTS = [3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3];

/** CBN 3-digit codes for commercial banks, matched by how people write the name. */
export const BANKS: ReadonlyArray<{ name: string; code: string; pattern: RegExp }> = [
  { name: "Access Bank", code: "044", pattern: /\baccess\b/i },
  { name: "GTBank", code: "058", pattern: /\b(gtb|gtbank|gtco|guaranty trust)\b/i },
  { name: "UBA", code: "033", pattern: /\b(uba|united bank for africa)\b/i },
  { name: "First Bank", code: "011", pattern: /\b(first ?bank)\b/i },
  { name: "Zenith Bank", code: "057", pattern: /\bzenith\b/i },
  { name: "Fidelity Bank", code: "070", pattern: /\bfidelity\b/i },
  { name: "FCMB", code: "214", pattern: /\b(fcmb|first city monument)\b/i },
  { name: "Union Bank", code: "032", pattern: /\bunion bank\b/i },
  { name: "Sterling Bank", code: "232", pattern: /\bsterling\b/i },
  { name: "Wema Bank", code: "035", pattern: /\bwema\b/i },
  { name: "Ecobank", code: "050", pattern: /\becobank\b/i },
];

/** The check digit for a 3-digit bank code and 9-digit serial. */
export function nubanCheckDigit(bankCode: string, serial: string): number {
  if (!/^\d{3}$/.test(bankCode) || !/^\d{9}$/.test(serial)) {
    throw new Error("bankCode must be 3 digits and serial 9 digits");
  }
  const digits = bankCode + serial;
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(digits[i]) * WEIGHTS[i];
  return (10 - (sum % 10)) % 10;
}

/** True when `account` is a valid 10-digit NUBAN for `bankCode`. */
export function isValidNuban(account: string, bankCode: string): boolean {
  if (!/^\d{10}$/.test(account)) return false;
  return nubanCheckDigit(bankCode, account.slice(0, 9)) === Number(account[9]);
}

/** The first bank named in `text`, if any. */
export function findBank(text: string) {
  return BANKS.find((b) => b.pattern.test(text));
}
