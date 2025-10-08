/*!
 * Copyright (c) 2019-2025 Digital Bazaar, Inc. All rights reserved.
 */
export const isBrowser = false;

export function base64Encode(bytes) {
  return Buffer.from(bytes.buffer, bytes.offset, bytes.length)
    .toString('base64');
}

export function base64urlEncode(bytes) {
  return Buffer.from(bytes.buffer, bytes.offset, bytes.length)
    .toString('base64url');
}
