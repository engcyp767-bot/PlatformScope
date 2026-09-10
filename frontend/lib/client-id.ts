/**
 * Creates a compact identifier in both secure and ordinary HTTP contexts.
 * `crypto.randomUUID()` is restricted to secure contexts in some browsers,
 * while `crypto.getRandomValues()` remains broadly available.
 */
export function createClientId(length = 12): string {
  const cryptoApi = typeof crypto !== 'undefined' ? crypto : undefined;

  if (typeof cryptoApi?.randomUUID === 'function') {
    return cryptoApi.randomUUID().replaceAll('-', '').slice(0, length);
  }

  const bytes = new Uint8Array(Math.ceil(length / 2));
  if (typeof cryptoApi?.getRandomValues === 'function') {
    cryptoApi.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }

  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, length);
}
