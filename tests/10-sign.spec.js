const {signCapabilityInvocation} = require('../index');

describe('signCapabilityInvocation', function() {
  it('should sign basic request', async function() {
    const signed = await signCapabilityInvocation({
      url: 'https://www.test.org/read/foo',
      method: 'GET',
      headers: {date: new Date().toUTCString()},
      json: {foo: true},
      invocationSigner: {
        id: 'did:test:foo',
        sign() {console.log('signed');}
      },
      capabilityAction: 'read'
    });
    console.log('signed', signed);
  });
});
