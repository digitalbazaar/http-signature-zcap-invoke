const {signCapabilityInvocation} = require('../index');
const {Ed25519KeyPair} = require('crypto-ld');
const {shouldBeAnAuthorizedRequest} = require('./test-assertions');

describe('signCapabilityInvocation', function() {
  let ed25519Key, keyId = null;
  before(async function() {
    ed25519Key = await Ed25519KeyPair.generate();
    keyId = 'did:key:foo';
    ed25519Key.id = keyId;
  });
  it('should sign a root zCap', async function() {
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
    console.log('signed', signed);
    shouldBeAnAuthorizedRequest(signed);
  });
});
