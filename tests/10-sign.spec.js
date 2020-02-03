const {signCapabilityInvocation} = require('../index');
const {Ed25519KeyPair} = require('crypto-ld');
const {shouldBeAnAuthorizedRequest} = require('./test-assertions');

// TODO verify results using zvap-verify

/**
 * Reading
 * @see https://w3c-ccg.github.io/zcap-ld/
 */

describe('signCapabilityInvocation', function() {
  let ed25519Key, keyId = null;
  before(async function() {
    ed25519Key = await Ed25519KeyPair.generate();
    keyId = 'did:key:foo';
    ed25519Key.id = keyId;
  });

  describe('should sign', function() {

    it('a valid root zCap', async function() {
      const invocationSigner = ed25519Key.signer();
      invocationSigner.id = keyId;
      const signed = await signCapabilityInvocation({
        url: 'https://www.test.org/read/foo',
        method: 'GET',
        headers: {
          keyId,
          date: new Date().toUTCString()
        },
        json: {foo: true},
        invocationSigner,
        capabilityAction: 'read'
      });
      shouldBeAnAuthorizedRequest(signed);
    });

    it('a valid zCap with a capability string', async function() {
      const invocationSigner = ed25519Key.signer();
      invocationSigner.id = keyId;
      const signed = await signCapabilityInvocation({
        url: 'https://www.test.org/read/foo',
        method: 'GET',
        headers: {
          keyId,
          date: new Date().toUTCString()
        },
        json: {foo: true},
        invocationSigner,
        capability: 'test',
        capabilityAction: 'read'
      });
      shouldBeAnAuthorizedRequest(signed);
    });

    it('a valid zCap with a capability object', async function() {
      const invocationSigner = ed25519Key.signer();
      invocationSigner.id = keyId;
      const signed = await signCapabilityInvocation({
        url: 'https://www.test.org/read/foo',
        method: 'GET',
        headers: {
          keyId,
          date: new Date().toUTCString()
        },
        json: {foo: true},
        invocationSigner,
        capability: {id: 'test'},
        capabilityAction: 'read'
      });
      shouldBeAnAuthorizedRequest(signed);
    });

  });

  describe('should NOT sign', function() {

    it('a root zCap with out a method', async function() {
      const invocationSigner = ed25519Key.signer();
      invocationSigner.id = keyId;
      let error, result = null;
      try {
        result = await signCapabilityInvocation({
          url: 'https://www.test.org/read/foo',
          method: undefined,
          headers: {
            keyId,
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
      error.code.should.exist;
      error.code.should.be.a('string');
      error.code.should.contain('ERR_ASSERTION');
    });

    it('a root zCap with out headers', async function() {
      const invocationSigner = ed25519Key.signer();
      invocationSigner.id = keyId;
      let error, result = null;
      try {
        result = await signCapabilityInvocation({
          url: 'https://www.test.org/read/foo',
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
      error.should.be.an.instanceOf(Error);
    });

    it.skip('a root zCap with out an invocationSigner', async function() {

    });

    it.skip('a root zCap with out a capabilityAction', async function() {

    });

    it.skip('a root zCap with out a url', async function() {

    });

  });
});
