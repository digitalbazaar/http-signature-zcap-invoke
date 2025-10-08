/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
export const isBrowser = true;

export function base64Encode(bytes) {
  if(bytes.toBase64) {
    return bytes.toBase64();
  }
  return btoa(Array.from(bytes, b => String.fromCodePoint(b)).join(''));
}

export function base64urlEncode(bytes) {
  if(bytes.toBase64) {
    return bytes.toBase64({alphabet: 'base64url', omitPadding: true});
  }
  return base64Encode(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replaceAll('=', '');
}
