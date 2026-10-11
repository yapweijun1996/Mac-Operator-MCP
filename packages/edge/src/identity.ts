const BROKER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

/**
 * The identity contract every Edge component must agree on before an identity
 * reaches the Broker: JWT claims, principal projection and rate-limit keys.
 * One definition keeps a token accepted here usable end to end.
 */
export function isBrokerId(value: unknown): value is string {
  return typeof value === "string" && BROKER_ID_PATTERN.test(value);
}
