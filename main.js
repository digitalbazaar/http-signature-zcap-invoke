/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import pako from 'pako';
import {TextEncoder, URL, base64Encode} from './util.js';
import {createAuthzHeader, createSignatureString} from 'http-signature-header';
import {createHeaderValue} from '@digitalbazaar/http-digest-header';

// detect browser environment
const isBrowser = (typeof self !== 'undefined');

/**
 * Signs an HTTP message to invoke a capability.
 *
 * @param {object} options - Options to use.
 * @param {string} options.url - The invocation target.
 * @param {string} options.method - An HTTP method.
 * @param {object} options.headers - The headers in the HTTP message.
 * @param {object} [options.json] - An optional json object representing an
 *   HTTP JSON body, if any.
 * @param {string|object} options.capability - Either a string or a capability
 *   object.
 * @param {object} options.invocationSigner - The invoker's key for signing.
 * @param {string} options.capabilityAction - The action(s) the capability
 *   can perform.
 * @param {string|Date|number} [options.created = now] - created is a
 *   psuedo-header used in the http signature.
 * @param {string|Date|number} [options.expires] - expires is a
 *   psuedo-header used to ensure the header signature expires.
 *
 * @returns {Promise<object>} Resolves to the signed headers.
 */
export async function signCapabilityInvocation({
  url,
  method,
  headers,
  json,
  capability = url,
  invocationSigner,
  capabilityAction,
  created = Math.floor(Date.now() / 1000),
  expires
}) {
  // we must have an invocationSigner
  if(!invocationSigner) {
    throw new TypeError('"invocationSigner" must be an object.');
  }
  // the invocationSigner must have a .sign method
  if(!invocationSigner.sign) {
    throw new TypeError('"invocationSigner.sign" must be a function.');
  }
  // the invocationSigner must have a .sign method
  if(typeof invocationSigner.sign !== 'function') {
    throw new TypeError('invocationSigner must have a sign method');
  }
  // lower case keys to ensure any updates apply properly
  const signed = _lowerCaseObjectKeys(headers);

  if(!('host' in signed)) {
    signed.host = new URL(url).host;
  }

  // a zCap must have a capability, this check removes `null` from consideration
  if(!capability) {
    throw new TypeError('"capability" must be a string or an object.');
  }
  let invocationHeader;
  if(typeof capability === 'string') {
    // build `capability-invocation` header; use ID of capability only
    invocationHeader = `zcap id="${capability}"`;
  } else if(typeof capability === 'object' && capability.id) {
    invocationHeader =
      `zcap capability="${base64url.encode(pako.gzip(
        JSON.stringify(capability)))}"`;
  } else {
    throw new TypeError('"capability" must be a string or an object.');
  }
  if(capabilityAction) {
    invocationHeader += `,action="${capabilityAction}"`;
  }
  signed['capability-invocation'] = invocationHeader;

  if(json && !('digest' in signed)) {
    // compute digest for json
    signed.digest = await createHeaderValue({data: json, useMultihash: true});

    if(!('content-type' in signed)) {
      signed['content-type'] = 'application/json';
    }
  }
  // convert dates to unix time stamp
  if(created instanceof Date) {
    created = Math.floor(created.getTime() / 1000);
  }
  // set expiration 10 minutes into the future
  expires = expires || Number.parseInt(created) + 600;

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
    algorithm: 'hs2019',
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
