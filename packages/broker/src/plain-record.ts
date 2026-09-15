/**
 * Accept only data-only records whose own properties are represented by the
 * canonical JSON/object-spread boundary. Accessors, hidden properties,
 * symbols, and prototype-provided authority are not request or policy data.
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
