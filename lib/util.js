/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
export const isBrowser = false;

export function base64Encode(data) {
  return Buffer.from(data, data.offset, data.length).toString('base64');
}
