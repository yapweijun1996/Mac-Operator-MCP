import { argon2, randomBytes, timingSafeEqual } from "node:crypto";

/** Fixed version-one costs prevent untrusted records from choosing allocation sizes. */
export async function derivePassword(password: string, salt: string): Promise<string> {
  if (typeof argon2 !== "function") throw new Error("Authentication requires Node 24.7 or newer");
  if (Buffer.byteLength(password) > 1024) throw new Error("Password too long");
  const bytes = Buffer.from(password);
  try {
    return await new Promise<string>((resolve, reject) => {
      argon2("argon2id", { message: bytes, nonce: Buffer.from(salt, "hex"), parallelism: 1, memory: 65536, passes: 3, tagLength: 32 }, (error, key) => {
        if (error) reject(new Error("Password hashing unavailable"));
        else { const encoded = key.toString("hex"); key.fill(0); resolve(encoded); }
      });
    });
  } finally { bytes.fill(0); }
}

export async function createPassword(password: string): Promise<{ salt: string; passwordHash: string }> {
  if (password.length < 14 || Buffer.byteLength(password) > 1024) throw new Error("Use a password of 14 or more characters (maximum 1024 bytes)");
  const salt = randomBytes(32).toString("hex");
  return { salt, passwordHash: await derivePassword(password, salt) };
}

export async function verifyPassword(password: string, salt: string, passwordHash: string): Promise<boolean> {
  const actual = await derivePassword(password, salt);
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(passwordHash, "hex"));
}
