var test = require('frisby');

test.create('Fixed authentication succeeded')
  .get('http://auth_fixed.local:1337/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('Fixed authentication failed on password: no fallback')
  .get('http://auth_fixed.local:1337/')
  .auth('alice', 'rabbit')
  .expectStatus(401)
  .toss();
test.create('Fixed authentication failed on login: fallback')
  .get('http://auth_fixed.local:1337/')
  .auth('mrwhite', 'alice')
  .expectStatus(200)
  .toss();

test.create('HTTP authentication succeeded')
  .get('http://auth_http.local:1337/')
  .auth('hatter', 'teaparty')
  .expectStatus(200)
  .toss();
// SECURITY WARNING: HTTP authentication does not provide ways to know which
// part of the credentials failed. Whatever its position in the authenticators
// list, it is always considered at the lowest priority.
test.create('HTTP authentication failed on password: fallback')
  .get('http://auth_http.local:1337/')
  .auth('mrwhite', 'alice')
  .expectStatus(200)
  .toss();

test.create('LDAP authentication succeeded')
  .get('http://auth_ldap.local:1337/')
  .auth('riemann', 'password')
  .expectStatus(200)
  .toss();
test.create('LDAP authentication failed on password: no fallback')
  .get('http://auth_ldap.local:1337/')
  .auth('riemann', 'secret')
  .expectStatus(401)
  .toss();
test.create('LDAP authentication failed on login: fallback')
  .get('http://auth_ldap.local:1337/')
  .auth('mrwhite', 'alice')
  .expectStatus(200)
  .toss();
