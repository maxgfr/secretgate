export interface LuhnOptions {
  stripSeparators?: boolean;
}

// Luhn checksum — used to keep the credit-card rule from firing on arbitrary
// digit runs (only checksum-valid numbers count as findings).
export function luhnValid(input: string, options: LuhnOptions = {}): boolean {
  const s = options.stripSeparators ? input.replace(/[ -]/g, "") : input;
  if (s.length === 0 || !/^\d+$/.test(s)) return false;
  let sum = 0;
  let double = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let digit = s.charCodeAt(i) - 48;
    if (double) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
}
