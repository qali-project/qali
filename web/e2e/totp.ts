import { createHmac } from "node:crypto";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input: string): Buffer {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of input.replace(/=+$/, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error(`invalid base32 character ${char}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) for one step. */
export function totpCode(secret: string, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const value = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

/**
 * An authenticator that never reuses a step: the server rejects replayed
 * codes, so each new code uses a later step, waiting for the next 30-second
 * window when the server's +/-1 step tolerance would be exceeded.
 */
export class Authenticator {
  private lastStep = 0;

  constructor(private readonly secret: string) {}

  async next(): Promise<string> {
    const now = Math.floor(Date.now() / 30_000);
    const step = Math.max(now, this.lastStep + 1);
    if (step > now + 1) {
      await new Promise((resolve) => setTimeout(resolve, (step - 1) * 30_000 - Date.now() + 250));
    }
    this.lastStep = step;
    return totpCode(this.secret, step);
  }
}
