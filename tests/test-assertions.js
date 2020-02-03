const shouldBeAnAuthorizedRequest = actualResult => {
  should.exist(actualResult);
  actualResult.should.be.an('object');
  actualResult.keyid.should.exist;
  actualResult.keyid.should.be.a('string');
  actualResult.date.should.exist;
  actualResult.date.should.be.a('string');
  actualResult.host.should.exist;
  actualResult.host.should.be.a('string');
  actualResult.authorization.should.exist;
  actualResult.authorization.should.be.a('string');
  actualResult.authorization.should.contain('keyId');
  actualResult.authorization.should.contain('headers');
  actualResult.authorization.should.contain('signature');
  actualResult['capability-invocation'].should.exist;
  actualResult['capability-invocation'].should.contain('zcap');
};

exports.shouldBeAnAuthorizedRequest = shouldBeAnAuthorizedRequest;
