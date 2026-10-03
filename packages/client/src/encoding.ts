const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * base64url without padding, as JOSE wants it.
 * @internal
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

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
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}

/** @internal */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** The decoded payload of a compact JWS, without verifying it. For reading `exp` off a token this client was just handed. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split('.');
  if (parts.length !== 3 || parts[1] === undefined) {
    throw new Error('Not a compact JWS.');
  }
  return JSON.parse(fromUtf8(base64UrlDecode(parts[1]))) as Record<string, unknown>;
}
