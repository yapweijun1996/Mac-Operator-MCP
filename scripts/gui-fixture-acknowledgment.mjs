export function ownedDocumentCleanupAcknowledged(value, expected) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && expected &&
    ["probe_id", "app_id", "document_title", "document_path", "window_id"].every(key =>
      Object.hasOwn(value, key) && value[key] === expected[key]) &&
    value.closed === true && value.independently_confirmed_absent === true);
}
