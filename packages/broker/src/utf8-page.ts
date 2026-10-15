/** Decode a bounded byte window, deferring only a valid incomplete final character. */
export function decodeUtf8Page(bytes: Uint8Array, hasMore: boolean): { content: string; bytesReturned: number } {
  const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes, { stream: hasMore });
  let end = bytes.length;
  if (hasMore && end > 0) {
    let start = end - 1;
    while (start > 0 && (bytes[start]! & 0xc0) === 0x80) start--;
    const lead = bytes[start]!;
    const length = lead >= 0xc2 && lead <= 0xdf ? 2 : lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xf0 && lead <= 0xf4 ? 4 : 1;
    if (end - start < length) end = start;
    if (end === 0) throw new RangeError("File read size cannot fit the next UTF-8 character");
  }
  return { content, bytesReturned: end };
}
