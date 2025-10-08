/*!
 * Copyright (c) 2020-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  createRootCapability,
  documentLoader as zcapDocLoader
} from '@digitalbazaar/zcap';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {constants as securityContextConstants} from 'security-context';
import {shouldBeAnAuthorizedRequest} from './test-assertions.js';
import {signCapabilityInvocation} from '../lib/index.js';
import {
  verifyCapabilityInvocation
} from '@digitalbazaar/http-signature-zcap-verify';

const {SECURITY_CONTEXT_V2_URL} = securityContextConstants;

/**
 * For further info see zcap-ld.
 *
 * @see https://w3c-ccg.github.io/zcap-ld/
 */

const invocationSignerError = new TypeError(
  '"invocationSigner" must be an object.');
const invocationSignerIdError = new TypeError(
  '"invocationSigner.id" must be a string.');
const invocationSignerSignError = new TypeError(
  '"invocationSigner.sign" must be a function.');
const capabilityError = new TypeError(
  '"capability" must be a string to invoke a root capability ' +
  'or an object to invoke a delegated capability.');

// Future Tests can expand this array
// to test additional LDKeyPairs
const keyPairs = [{
  name: 'Ed25519VerificationKey2020',
  KeyPair: Ed25519Multikey,
  Suite: Ed25519Signature2020
}];

const TEST_URL = 'https://www.test.org/read/foo';
const method = 'GET';
const controller = 'did:test:controller';
const rootCapability = createRootCapability(
  {controller, invocationTarget: TEST_URL});

const verify = async ({signed, Suite, keyPair}) => {
  const {host} = new URL(TEST_URL);
  signed.host = signed.host || host;

  const keyId = keyPair.id;

  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });
  const documentLoader = async uri => {
    if(uri === controller) {
      const doc = {
        '@context': SECURITY_CONTEXT_V2_URL,
        id: controller,
        capabilityInvocation: [keyId]
      };
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    // when we dereference the keyId for verification
    // all we need is the publicNode
    if(uri === keyId) {
      const doc = await keyPair.export({publicKey: true, includeContext: true});
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    if(uri === rootCapability.id) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    return zcapDocLoader(uri);
  };
  const {verified, error} = await verifyCapabilityInvocation({
    url: TEST_URL,
    method,
    suite,
    headers: signed,
    expectedAction: 'read',
    expectedHost: host,
    expectedRootCapability: rootCapability.id,
    expectedTarget: TEST_URL,
    keyId,
    documentLoader,
    getVerifier
  });
  should.exist(verified);
  should.not.exist(error);
  verified.should.be.a('boolean');
  verified.should.equal(true);
};

describe('signCapabilityInvocation', function() {
  const keyId = 'did:key:foo';
  describe('should sign with a(n)', function() {
    keyPairs.forEach(function(keyType) {
      describe(keyType.name, function() {
        let invocationSigner;
        let keyPair = null;
        const {KeyPair, Suite} = keyType;
        beforeEach(async function() {
          const _id = `${keyId}:${crypto.randomUUID()}`;
          keyPair = await KeyPair.generate({controller, id: _id});
          invocationSigner = keyPair.signer();
        });

        it('a valid root zCap', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });

        it('a valid zCap with a capability string', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capability: rootCapability.id,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });

        it('a valid zCap with a capability object', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capability: rootCapability,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });

        it('a valid root zCap with host in the headers', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              host: 'www.test.org',
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });

        it('a valid root zCap with body typeless Blob', async function() {
          const nonce1 = crypto.randomUUID();
          const body1 = new Blob([nonce1]);
          // default options for signCapabilityInvocation
          const invocationBase = {
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            invocationSigner,
            capabilityAction: 'read'
          };
          const signed = await signCapabilityInvocation({
            ...invocationBase,
            body: body1,
          });

          shouldBeAnAuthorizedRequest(signed);

          should.equal(typeof signed.digest, 'string',
            `signed headers should include Digest string`);

          // no content-type because body1 has no .type
          should.not.exist(signed['content-type']);
          // the authorization header should not sign over content-type,
          // because body1 has no .type
          should.not.equal(signed.authorization.includes('content-type'), true);

          await verify({signed, Suite, keyPair});

          // above could all pass if there is a bug in the common
          // digest function used by `signCapabilityInvocation` and `verify`
          // e.g. if digest function always just digests everything the same.
          // ensure digests for different bodies are different.
          const nonce2 = crypto.randomUUID();
          const body2 = new Blob([nonce2]);
          const signedBody2 = await signCapabilityInvocation({
            ...invocationBase,
            body: body2,
          });
          should.not.equal(signed.digest, signedBody2.digest,
            `digests differ when body buffers differ`);
        });

        it('a valid root zCap with non-JSON body Blob', async function() {
          const nonce1 = crypto.randomUUID();
          const body1 = new Blob([nonce1], {type: `text/plain+${nonce1}`});
          /**
           * @param {Blob} body - Body of http request that should be signed.
           */
          async function signBody(body) {
            return signCapabilityInvocation({
              url: TEST_URL,
              method,
              headers: {
                date: new Date().toUTCString()
              },
              body,
              invocationSigner,
              capabilityAction: 'read'
            });
          }
          const signed = await signBody(body1);
          shouldBeAnAuthorizedRequest(signed);
          should.equal(typeof signed.digest, 'string',
            `signed headers should include Digest string`);
          should.exist(signed['content-type']);
          signed['content-type'].should.be.a('string');
          signed['content-type'].should.equal(body1.type);
          await verify({signed, Suite, keyPair});

          // above could all pass if there is a bug in the common
          // digest function used by `signCapabilityInvocation` and `verify`.
          // e.g. if digest function always just digests everything the same.
          // ensure digests for different bodies are different.
          const nonce2 = crypto.randomUUID();
          const body2 = new Blob([nonce2], {type: body1.type});
          const signedBody2 = await signBody(body2);
          should.not.equal(signed.digest, signedBody2.digest,
            `digests differ when body buffers differ`);
        });

        it('a valid root zCap with non-JSON body Uint8Array', async function() {
          const body1 = new Uint8Array([1, 2, 3]);
          /**
           * @param {Uint8Array} body - Body of http request that should be
           * signed.
           */
          async function signBody(body) {
            return signCapabilityInvocation({
              url: TEST_URL,
              method,
              headers: {
                date: new Date().toUTCString()
              },
              body,
              invocationSigner,
              capabilityAction: 'read'
            });
          }
          const signed = await signBody(body1);
          shouldBeAnAuthorizedRequest(signed);
          should.equal(typeof signed.digest, 'string',
            `signed headers should include Digest string`);
          should.exist(signed['content-type']);
          signed['content-type'].should.be.a('string');
          signed['content-type'].should.equal('application/octet-stream');
          await verify({signed, Suite, keyPair});

          // above could all pass if there is a bug in the common
          // digest function used by `signCapabilityInvocation` and `verify`.
          // e.g. if digest function always just digests everything the same.
          // ensure digests for different bodies are different.
          const body2 = new Uint8Array([4, 5, 6]);
          const signedBody2 = await signBody(body2);
          should.not.equal(signed.digest, signedBody2.digest,
            `digests differ when body buffers differ`);
        });

        it('a valid root zCap with Uint8Array w/plain text', async function() {
          const body1 = new TextEncoder().encode('abc');
          /**
           * @param {Uint8Array} body - Body of http request that should be
           * signed.
           */
          async function signBody(body) {
            return signCapabilityInvocation({
              url: TEST_URL,
              method,
              headers: {
                date: new Date().toUTCString(),
                'content-type': 'text/plain'
              },
              body,
              invocationSigner,
              capabilityAction: 'read'
            });
          }
          const signed = await signBody(body1);
          shouldBeAnAuthorizedRequest(signed);
          should.equal(typeof signed.digest, 'string',
            `signed headers should include Digest string`);
          should.exist(signed['content-type']);
          signed['content-type'].should.be.a('string');
          signed['content-type'].should.equal('text/plain');
          await verify({signed, Suite, keyPair});

          // above could all pass if there is a bug in the common
          // digest function used by `signCapabilityInvocation` and `verify`.
          // e.g. if digest function always just digests everything the same.
          // ensure digests for different bodies are different.
          const body2 = new TextEncoder().encode('def');
          const signedBody2 = await signBody(body2);
          should.not.equal(signed.digest, signedBody2.digest,
            `digests differ when body buffers differ`);
        });

        it('a valid root zCap with json', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          should.exist(signed['content-type']);
          signed['content-type'].should.be.a('string');
          signed['content-type'].should.contain('application/json');
          await verify({signed, Suite, keyPair});
        });

        it('a valid root zCap without json', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          should.not.exist(signed.digest);
          await verify({signed, Suite, keyPair});
        });

        it('a valid root zCap with digest', async function() {
          const digest = 'f93a541ae8cd64d13d4054abacccb1cb';
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              digest,
              date: new Date().toUTCString()
            },
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          signed.digest.should.equal(digest);
          await verify({signed, Suite, keyPair});
        });

        it('a valid root zCap with UPPERCASE headers', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              DATE: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });
      });
    });
  });

  describe('should NOT sign with a(n) ', function() {
    keyPairs.forEach(function(keyType) {
      describe(keyType.name, function() {
        let invocationSigner = null;
        const {KeyPair} = keyType;
        beforeEach(async function() {
          const invocationKeyPair = await KeyPair
            .generate({id: `${keyId}:${crypto.randomUUID()}`});
          invocationSigner = invocationKeyPair.signer();
        });

        it('a zCap without a capability', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              method,
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              invocationSigner,
              capability: null,
              capabilityAction: 'read'
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.should.be.an.instanceOf(Error);
          error.cause.message.should.equal(capabilityError.message);
        });

        it('a root zCap without a capabilityAction', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              method,
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              invocationSigner,
              capability: null,
              capabilityAction: null
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.should.be.an.instanceOf(Error);
          error.cause.message.should.contain(
            '"capabilityAction" must be a string.');
        });

        it('a root zCap without a HTTP method', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              invocationSigner,
              capabilityAction: 'read'
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.cause.should.be.an.instanceOf(TypeError);
          error.cause.message.should.contain(
            '"method" must be a string.');
        });

        it('a root zCap without headers', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              method: 'post',
              headers: undefined,
              json: {foo: true},
              invocationSigner,
              capabilityAction: 'read'
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.cause.should.be.an.instanceOf(TypeError);
          error.cause.name.should.contain('TypeError');
          error.cause.message.should.contain(
            'Cannot convert undefined or null to object');
        });

        it('a root zCap without an invocationSigner', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              method: 'post',
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              capabilityAction: 'read'
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.cause.should.be.an.instanceOf(TypeError);
          error.cause.message.should.equal(invocationSignerError.message);
          error.cause.name.should.equal(invocationSignerError.name);
        });

        it('a root zCap without an invocationSigner.sign method',
          async function() {
            // remove the sign method
            delete invocationSigner.sign;
            let error;
            let result = null;
            try {
              result = await signCapabilityInvocation({
                url: TEST_URL,
                method: 'post',
                headers: {
                  date: new Date().toUTCString()
                },
                json: {foo: true},
                capabilityAction: 'read',
                invocationSigner
              });
            } catch(e) {
              error = e;
            }
            should.not.exist(result);
            should.exist(error);
            error.cause.should.be.an.instanceOf(TypeError);
            error.cause.message.should.equal(invocationSignerSignError.message);
            error.cause.name.should.equal(invocationSignerSignError.name);
          });

        it('a root zCap with an invocationSigner.id that is not a string',
          async function() {
            // omit `id`
            delete invocationSigner.id;
            let error;
            let result = null;
            try {
              result = await signCapabilityInvocation({
                url: TEST_URL,
                method: 'post',
                headers: {
                  date: new Date().toUTCString()
                },
                json: {foo: true},
                capabilityAction: 'read',
                invocationSigner
              });
            } catch(e) {
              error = e;
            }
            should.not.exist(result);
            should.exist(error);
            error.cause.should.be.an.instanceOf(TypeError);
            error.cause.message.should.equal(invocationSignerIdError.message);
            error.cause.name.should.equal(invocationSignerIdError.name);
          });

        it('a root zCap with an invocationSigner.sign that is not a function',
          async function() {
            // erroneously set `sign` to a string instead of a function
            invocationSigner.sign = 'foo';
            let error;
            let result = null;
            try {
              result = await signCapabilityInvocation({
                url: TEST_URL,
                method: 'post',
                headers: {
                  date: new Date().toUTCString()
                },
                json: {foo: true},
                capabilityAction: 'read',
                invocationSigner
              });
            } catch(e) {
              error = e;
            }
            should.not.exist(result);
            should.exist(error);
            error.cause.should.be.an.instanceOf(TypeError);
            error.cause.message.should.equal(invocationSignerSignError.message);
            error.cause.name.should.equal(invocationSignerSignError.name);
          });

        it('a root zCap without a url and host', async function() {
          let error;
          let result = null;
          try {
            result = await signCapabilityInvocation({
              method: 'post',
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              invocationSigner,
              capabilityAction: 'read'
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.should.be.an.instanceOf(Error);
          error.cause.name.should.contain('TypeError');
          error.cause.message.should.contain('Invalid URL');
        });
      });
    });
  });
});

async function getVerifier({keyId, documentLoader}) {
  const {document} = await documentLoader(keyId);
  const key = await Ed25519Multikey.from(document);
  if(key.revoked) {
    throw new Error('Verification method has been revoked.');
  }
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}
