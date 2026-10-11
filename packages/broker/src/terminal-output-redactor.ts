import { StringDecoder } from "node:string_decoder";
import { redactBoundedText } from "./secret-policy.js";

const MAX_PENDING_BYTES = 65_536;
const PRIVATE_KEY_START = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u;
const PRIVATE_KEY_END = /-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u;
// These labels can acquire a secret value after whitespace in a later chunk.
const OPEN_SECRET_LABEL = /(?<![A-Za-z0-9])(?:X-Amz-Signature|X-Amz-Security-Token|api[_-]?key|client[_-]?secret|password|passwd|secret|token|aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*(?:[:=]\s*["']?)?$|\b(?:Bearer|Basic)\s*$/iu;

/** Publishes only stable, sanitized text, independent of process chunks and read pages. */
export class TerminalOutputRedactor {
  private readonly decoder = new StringDecoder("utf8");
  private pending = "";
  private discarding: "private-key" | "oversized" | undefined;

  push(chunk: Buffer): string {
    let output = "";
    // Bound pending state even if a producer supplies a very large chunk.
    for (let offset = 0; offset < chunk.length; offset += 8_192) {
      this.pending += this.decoder.write(chunk.subarray(offset, offset + 8_192));
      output += this.drain(false);
    }
    return output;
  }

  finish(): string {
    this.pending += this.decoder.end();
    return this.drain(true);
  }

  private drain(final: boolean): string {
    let output = "";
    while (this.pending.length > 0) {
      if (this.discarding === "private-key") {
        const end = PRIVATE_KEY_END.exec(this.pending);
        if (!end) {
          this.pending = final ? "" : this.pending.slice(-128);
          break;
        }
        this.pending = this.pending.slice(end.index + end[0].length);
        this.discarding = undefined;
        continue;
      }
      if (this.discarding === "oversized") {
        const newline = this.pending.search(/[\r\n]/u);
        const start = PRIVATE_KEY_START.exec(this.pending);
        if (start && (newline < 0 || start.index < newline)) {
          this.pending = this.pending.slice(start.index + start[0].length);
          this.discarding = "private-key";
          continue;
        }
        if (newline >= 0) {
          output += this.pending[newline];
          this.pending = this.pending.slice(newline + 1);
          this.discarding = undefined;
          continue;
        }
        const marker = this.pendingPrivateHeader();
        this.pending = final ? "" : marker === undefined ? this.pending.slice(-4) : this.pending.slice(marker);
        if (Buffer.byteLength(this.pending, "utf8") > MAX_PENDING_BYTES) {
          this.discarding = "private-key";
          this.pending = this.pending.slice(-128);
        }
        break;
      }
      const start = PRIVATE_KEY_START.exec(this.pending);
      if (start) {
        output += this.redact(this.pending.slice(0, start.index)) + "[REDACTED]";
        this.pending = this.pending.slice(start.index + start[0].length);
        this.discarding = "private-key";
        continue;
      }
      if (final) {
        output += this.redact(this.pending);
        this.pending = "";
        break;
      }
      const newline = Math.max(this.pending.lastIndexOf("\n"), this.pending.lastIndexOf("\r"));
      const marker = this.pendingPrivateHeader();
      let end = newline + 1;
      if (end === 0) {
        // Complete ordinary words and prompts can stream before a newline.
        // Paths and PEM markers may include spaces, so retain their whole record.
        if (!this.pending.includes("/") && marker === undefined) {
          for (const match of this.pending.matchAll(/\s/gu)) end = match.index! + match[0].length;
        }
      }
      if (end > 0) {
        const candidate = this.pending.slice(0, end);
        const label = OPEN_SECRET_LABEL.exec(candidate);
        if (label) {
          const beforeLabel = candidate.slice(0, label.index);
          const lineStart = Math.max(beforeLabel.lastIndexOf("\n"), beforeLabel.lastIndexOf("\r")) + 1;
          // A credential-like basename belongs to its complete path record;
          // detaching it would lose the protected-path redaction context.
          end = beforeLabel.slice(lineStart).includes("/") ? lineStart : label.index;
        }
        // Keep a partial PEM marker until its complete header is available.
        if (marker !== undefined) end = Math.min(end, marker);
        if (end > 0) {
          output += this.redact(this.pending.slice(0, end));
          this.pending = this.pending.slice(end);
          continue;
        }
      }
      if (Buffer.byteLength(this.pending, "utf8") > MAX_PENDING_BYTES) {
        output += "[REDACTED: oversized terminal record]";
        this.discarding = marker === undefined ? "oversized" : "private-key";
        // Preserve only the tail needed to detect a split delimiter/footer.
        this.pending = this.pending.slice(-128);
        continue;
      }
      break;
    }
    return output;
  }

  private redact(text: string): string {
    return redactBoundedText(text, Math.max(1, Buffer.byteLength(text, "utf8") * 10)).text;
  }

  private pendingPrivateHeader(): number | undefined {
    for (const match of this.pending.matchAll(/-----/gu)) {
      const suffix = this.pending.slice(match.index);
      if ("-----BEGIN ".startsWith(suffix) || /^-----BEGIN [A-Z0-9 ]*(?:-{1,4})?$/u.test(suffix)) return match.index;
    }
    return undefined;
  }
}
