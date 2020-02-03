/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import crypto from './crypto.js';
import {TextEncoder, URL, base64Encode} from './util.js';
import {createAuthzHeader, createSignatureString} from 'http-signature-header';

// detect browser environment
const isBrowser = (typeof self !== 'undefined');

/**
 * Signs an HTTP message with a capability.
 *
 * @param {object} options - Options to use.
 * @param {string} options.url - The invocation target.
 * @param {string} options.method - An HTTP method.
 * @param {object} options.headers - The headers in the HTTP message.
 * @param {object} options.json - A json object.
 * @param {string|object} options.capability - Either a string or a capability
 *   object.
 * @param {object} options.invocationSigner - The invokver's key for signing.
 * @param {string|array} options.capabilityAction - The action(s) the capability
 *   can perform.
 *
 * @returns {object} The signed headers.
 */
export async function signCapabilityInvocation({
  url, method, headers, json, capability = url, invocationSigner,
  capabilityAction
}) {
  if(!invocationSigner) {
    throw new Error('invocationSigner required');
  }
  // lower case keys to ensure any updates apply properly
  const signed = _lowerCaseObjectKeys(headers);

  if(!('host' in signed)) {
    signed.host = new URL(url).host;
  }

  // build `capability-invocation` header; use ID of capability only
  if(typeof capability === 'object') {
    capability = capability.id;
  }
  let invocationHeader = `zcap id="${capability}"`;
  if(capabilityAction) {
    invocationHeader += `,action="${capabilityAction}"`;
  }
  signed['capability-invocation'] = invocationHeader;

  if(json && !('digest' in signed)) {
    // compute digest for json
    const data = new TextEncoder().encode(JSON.stringify(json));
    const digest = new Uint8Array(
      await crypto.subtle.digest({name: 'SHA-256'}, data));
    // format as multihash digest
    // sha2-256: 0x12, length: 32 (0x20), digest value
    const mh = new Uint8Array(34);
    mh[0] = 0x12;
    mh[1] = 0x20;
    mh.set(digest, 2);
    // encode multihash using multibase, base64url: `u`
    signed.digest = `mh=u${base64url.encode(mh)}`;
    if(!('content-type' in signed)) {
      signed['content-type'] = 'application/json';
    }
  }

  // TODO: allow for parameter for expiration window
  // set expiration 10 minutes into the future
  const created = Date.now();
  const expires = new Date(created + 600000).getTime();

  // sign header
  const {id: keyId} = invocationSigner;
  const includeHeaders = [
    '(key-id)', '(created)', '(expires)', '(request-target)',
    'host', 'capability-invocation'];
  if(json) {
    includeHeaders.push('content-type');
    includeHeaders.push('digest');
  }
  const plaintext = createSignatureString({
    includeHeaders,
    requestOptions: {url, method, headers: signed, created, expires, keyId}
  });
  const data = new TextEncoder().encode(plaintext);
  const signature = base64Encode(await invocationSigner.sign({data}));

  signed.authorization = createAuthzHeader({
    includeHeaders,
    keyId,
    signature,
    created,
    expires
  });

  // detect browser environment
  if(isBrowser) {
    // remove `host` header as it will be automatically set by the browser
    delete signed.host;
  }

  return signed;
}

function _lowerCaseObjectKeys(obj) {
  const newObject = {};
  for(const k of Object.keys(obj)) {
    newObject[k.toLowerCase()] = obj[k];
  }
  return newObject;
}
