var test = require('frisby');

test.create('Preserve HTTP basic authentication')
  .get('http://couchdb.local:1337/_active_tasks')
  .auth('carroll', 'curiouser')
  .expectStatus(200)
  .toss();
test.create('Preserve cookie authentication')
  .post('http://couchdb.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(200)
  .after(function(error, resource) {
    test.create('Preserve cookie authentication use')
      .get('http://couchdb.local:1337/_active_tasks')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(200)
      .toss();
  })
  .toss();
test.create('Do not preserve cookie authentication if failed locally')
  .post('http://xcouchdb.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(401)
  .after(function(error, resource) {
    test.create('Do not preserve cookie authentication use if failed locally')
      .get('http://xcouchdb.local:1337/_active_tasks')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(401)
      .toss();
  })
  .toss();
test.create('Preserve cookie authentication as a fallback')
  .post('http://xxcouchdb.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(200)
  .after(function(error, resource) {
    test.create('Preserve cookie authentication use as a fallback')
      .get('http://xxcouchdb.local:1337/_active_tasks')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(200)
      .toss();
  })
  .toss();
