/**
 * Accept only data-only records and arrays at configuration boundaries.
 * Accessors, hidden properties, symbols, and inherited authority are not
 * trusted configuration.
 */
export function isPlainDataRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length > 0 || names.length !== Object.keys(value).length) return false;
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function isPlainDataArray(value: unknown, maxLength = Number.MAX_SAFE_INTEGER): value is readonly unknown[] {
  if (!Array.isArray(value)) return false;
  try {
    if (value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || Object.keys(value).length !== value.length) return false;
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
      if (name !== "length" && (!/^(?:0|[1-9][0-9]*)$/u.test(name) || Number(name) >= value.length)) return false;
    }
    return true;
  } catch {
    return false;
  }
}
