const uuid = require('uuid-random');
const {signCapabilityInvocation} = require('../main');
const {shouldBeAnAuthorizedRequest} = require('./test-assertions');
const {verifyCapabilityInvocation} = require('http-signature-zcap-verify');

const {constants: {SECURITY_CONTEXT_V2_URL}} = require('security-context');

const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');
const {Ed25519Signature2020} = require('@digitalbazaar/ed25519-signature-2020');

/**
 * Reading
 * @see https://w3c-ccg.github.io/zcap-ld/
 */

const invocationSignerError = new TypeError(
  '"invocationSigner" must be an object.');
const invocationSignError = new TypeError(
  '"invocationSigner.sign" must be a function.');
const capabilityError = new TypeError(
  '"capability" must be a string or an object.');

// Future Tests can expand this array
// to test additional LDKeyPairs
const keyPairs = [{
  name: 'Ed25519VerificationKey2020',
  KeyPair: Ed25519VerificationKey2020,
  Suite: Ed25519Signature2020
}];

const TEST_URL = 'https://www.test.org/read/foo';
const method = 'GET';
const controller = 'did:test:controller';
const rootCapability = {
  '@context': SECURITY_CONTEXT_V2_URL,
  id: TEST_URL,
  invocationTarget: TEST_URL,
  controller,
  invoker: null
};

const verify = async ({signed, Suite, keyPair}) => {
  const {host} = new URL(TEST_URL);
  signed.host = signed.host || host;

  const keyId = keyPair.id;
  rootCapability.invoker = keyId;

  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });
  const documentLoader = async uri => {
    if(uri === controller) {
      const doc = {
        id: controller,
        '@context': SECURITY_CONTEXT_V2_URL,
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
      const doc = keyPair.export({publicKey: true, includeContext: true});
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    if(uri === TEST_URL) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    throw new Error(`documentLoader unable to resolve "${uri}"`);
  };
  const getInvokedCapability = () => rootCapability;
  const {verified, error} = await verifyCapabilityInvocation({
    url: TEST_URL,
    method,
    suite,
    expectedHost: host,
    headers: signed,
    expectedTarget: TEST_URL,
    keyId,
    documentLoader,
    getInvokedCapability
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
          const _id = `${keyId}:${uuid()}`;
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
            capability: 'test',
            capabilityAction: 'read'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
        });

        it('a valid zCap with a capability object', async function() {
          rootCapability.invoker = keyPair.id;
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

        it('a valid root zCap with a capabilityAction', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capabilityAction: 'action'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
          await verify({signed, Suite, keyPair});
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

        it('a valid root zCap with out json', async function() {
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

        it('a root zCap with out a capabilityAction', async function() {
          const signed = await signCapabilityInvocation({
            url: TEST_URL,
            method,
            headers: {
              date: new Date().toUTCString()
            },
            json: {foo: true},
            invocationSigner,
            capability: 'test'
          });
          shouldBeAnAuthorizedRequest(signed);
          signed.digest.should.exist;
          signed.digest.should.be.a('string');
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
            .generate({id: `${keyId}:${uuid()}`});
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
          error.cause.message.should.contain(
            '"capability" must be a string or an object.');
        });

        it('a root zCap with out a HTTP method', async function() {

          // detect browser environment
          const isBrowser = (typeof self !== 'undefined');
          // this test does not fail in browsers because
          // assert-plus is disabled in browsers in http-signature-header
          if(isBrowser) {
            this.skip();
          }
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

        it('a root zCap with out headers', async function() {
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

        it('a root zCap with out an invocationSigner', async function() {
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

        it('a root zCap with out an invocationSigner.sign method',
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
            error.cause.message.should.equal(invocationSignError.message);
            error.cause.name.should.equal(invocationSignError.name);
          });

        it('a root zCap with an invocationSigner.sign that is not a function',
          async function() {
            // remove the sign method
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
            error.cause.message.should.equal(
              'invocationSigner must have a sign method');
            error.cause.name.should.equal(invocationSignError.name);
          });

        it('a root zCap with out a url and host', async function() {
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

        it('a zCap if the capability object has no id', async function() {
          let result;
          let error = null;
          try {
            result = await signCapabilityInvocation({
              url: TEST_URL,
              method: 'GET',
              headers: {
                date: new Date().toUTCString()
              },
              json: {foo: true},
              invocationSigner,
              capability: {}
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.cause.should.be.an.instanceOf(TypeError);
          error.cause.message.should.equal(capabilityError.message);
          error.cause.name.should.equal(capabilityError.name);
        });
      });
    });
  });
});
