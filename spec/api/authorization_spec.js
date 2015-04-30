var test = require('frisby');

test.create('Public authorization with anonymous read')
  .get('http://cassandre.local:1337/text/')
  .expectStatus(200)
  .toss();
test.create('Public authorization with valid user read')
  .get('http://cassandre.local:1337/text/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('Public authorization with anonymous write')
  .post('http://cassandre.local:1337/', {}, {json:true})
  .expectStatus(401)
  .toss();
test.create('Public authorization with valid user write')
  .post('http://cassandre.local:1337/', {}, {json:true})
  .auth('alice', 'whiterabbit')
  .expectStatus(201)
  .toss();
test.create('Community authorization with anonymous')
  .get('http://cassandre.local:1337/text/Wonderland/')
  .expectStatus(401)
  .toss();
test.create('Community authorization with valid user')
  .get('http://cassandre.local:1337/text/Wonderland/')
  .auth('alice', 'whiterabbit')
  .expectStatus(200)
  .toss();
test.create('Private authorization with other user')
  .get('http://cassandre.local:1337/text/Wonderland/iamlate')
  .auth('alice', 'whiterabbit')
  .expectStatus(401)
  .toss();
test.create('Private authorization with owner')
  .get('http://cassandre.local:1337/text/Wonderland/iamlate')
  .auth('mrwhite', 'alice')
  .expectStatus(200)
  .toss();
