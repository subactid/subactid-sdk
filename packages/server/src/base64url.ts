const decoder = new TextDecoder();

/** @internal */
export function base64UrlDecode(text: string): Uint8Array<ArrayBuffer> {
  const padded = text
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(text.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** @internal */
export function decodeJson(segment: string): unknown {
  return JSON.parse(decoder.decode(base64UrlDecode(segment)));
}

/** @internal */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text);
}
