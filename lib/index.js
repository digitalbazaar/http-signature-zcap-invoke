/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  base64Encode,
  isBrowser
} from './util.js';
import {encode as base64UrlEncode} from 'base64url-universal';
import {
  createAuthzHeader, createSignatureString
} from '@digitalbazaar/http-signature-header';
import {createHeaderValue} from '@digitalbazaar/http-digest-header';
import pako from 'pako';

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

/**
 * Signs an HTTP message to invoke a capability. The `url` will be used as the
 * invocation target.
 *
 * @param {object} options - Options to use.
 * @param {string} options.url - The invocation target.
 * @param {string} options.method - An HTTP method.
 * @param {object} options.headers - The headers in the HTTP message.
 * @param {object} [options.json] - An optional json object representing an
 *   HTTP JSON body, if any.
 * @param {string|object} options.capability - Either a string to invoke a root
 *   zcap or a capability object to invoke a delegated zcap; this defaults to
 *   the root zcap expected to be associated with the url.
 * @param {string} options.capabilityAction - The action to perform with the
 *   capability.
 * @param {object} options.invocationSigner - An invocation signer object that
 *   includes an `id` representing the key ID for verification of the HTTP
 *   signature and a `sign` function that takes the `{data}` to sign and
 *   returns a signature.
 * @param {string|Date|number} [options.created=now] - The signature creation
 *   date to use in the created pseudo-header in the http signature.
 * @param {string|Date|number} [options.expires] - The expiration date to
 *   use in the expires pseudo-header; it ensures the header signature expires.
 *
 * @returns {Promise<object>} Resolves to the signed headers.
 */
export async function signCapabilityInvocation({
  url,
  method,
  headers,
  json,
  capability = `${ZCAP_ROOT_PREFIX}${encodeURIComponent(url)}`,
  capabilityAction,
  invocationSigner,
  created = Math.floor(Date.now() / 1000),
  expires
}) {
  try {
    if(!(method && typeof method === 'string')) {
      throw new TypeError('"method" must be a string.');
    }
    if(!(capabilityAction && typeof capabilityAction === 'string')) {
      throw new TypeError('"capabilityAction" must be a string.');
    }
    if(!(invocationSigner && typeof invocationSigner === 'object')) {
      throw new TypeError('"invocationSigner" must be an object.');
    }
    if(!(invocationSigner.id &&
      typeof invocationSigner.id === 'string')) {
      throw new TypeError('"invocationSigner.id" must be a string.');
    }
    if(!(invocationSigner.sign &&
      typeof invocationSigner.sign === 'function')) {
      throw new TypeError('"invocationSigner.sign" must be a function.');
    }
    if(!(capability && (typeof capability === 'string' ||
      typeof capability === 'object'))) {
      throw new TypeError(
        '"capability" must be a string to invoke a root capability or an ' +
        'object to invoke a delegated capability.');
    }

    // if capability is a root zcap, use just its ID
    if(typeof capability === 'object' && !capability.parentCapability) {
      capability = capability.id;
    }

    // lower case keys to ensure any updates apply properly
    const signed = _lowerCaseObjectKeys(headers);

    if(signed.host === undefined) {
      signed.host = new URL(url).host;
    }

    let invocationHeader;
    if(typeof capability === 'string') {
      // build `capability-invocation` header; use ID of capability only; only
      // valid for root zcap invocation
      invocationHeader = `zcap id="${capability}"`;
    } else {
      // only valid for delegated zcaps
      invocationHeader =
        `zcap capability="${base64UrlEncode(pako.gzip(
          JSON.stringify(capability)))}"`;
    }
    if(capabilityAction) {
      invocationHeader += `,action="${capabilityAction}"`;
    }
    signed['capability-invocation'] = invocationHeader;

    if(json && signed.digest === undefined) {
      // compute digest for json
      signed.digest = await createHeaderValue({data: json, useMultihash: true});

      if(signed['content-type'] === undefined) {
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
  } catch(cause) {
    const error = new Error(
      'Error signing capability invocation.\n' +
      `method: "${method}",\n` +
      `url: "${url}",\n` +
      `action: "${capabilityAction}"\n`);
    error.cause = cause;
    throw error;
  }
}

function _lowerCaseObjectKeys(obj) {
  const newObject = {};
  for(const k of Object.keys(obj)) {
    newObject[k.toLowerCase()] = obj[k];
  }
  return newObject;
}
