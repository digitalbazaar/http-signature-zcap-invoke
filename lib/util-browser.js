/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
export const isBrowser = true;

export function base64Encode(data) {
  return btoa(String.fromCharCode.apply(null, data));
}
