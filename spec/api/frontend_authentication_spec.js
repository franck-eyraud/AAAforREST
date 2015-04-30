var test = require('frisby');

test.create('HTTP basic authentication')
  .get('http://cassandre.local:1337/text/Wonderland/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('HTTP cookie authentication')
  .post('http://cassandre.local:1337/_session', {name:'alice', password:'whiterabbit'})
  .expectStatus(200)
  .after(function(error, resource) {
    test.create('HTTP cookie authentication use')
      .get('http://cassandre.local:1337/text/Wonderland/')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(200)
      .toss();
  })
  .toss();
