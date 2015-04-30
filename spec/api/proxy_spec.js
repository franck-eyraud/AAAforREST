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
  .post('http://sessiontf.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(401)
  .after(function(error, resource) {
    test.create('Do not preserve cookie authentication use if failed locally')
      .get('http://sessiontf.local:1337/_active_tasks')
      .addHeader('Cookie', resource.headers['set-cookie'])
      .expectStatus(401)
      .toss();
  })
  .toss();
test.create('Preserve cookie authentication as a fallback')
  .post('http://sessiontt.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(200)
  .after(function(error, resource) {
    var cookie=resource.headers['set-cookie'];
    test.create('Preserve cookie authentication use as a fallback')
      .get('http://sessiontt.local:1337/_active_tasks')
      .addHeader('Cookie', cookie)
      .expectStatus(200)
      .after(function(error,resource) {
        test.create('Remove fallback session cookie')
          .delete('http://sessiontt.local:1337/_session')
          .addHeader('Cookie', cookie)
          .expectStatus(200)
          .after(function(error,resurce) {
            test.create('Fallback cookie correctly removed')
              .get('http://sessiontt.local:1337/_active_tasks')
              .addHeader('Cookie', resource.headers['set-cookie'])
              .expectStatus(401)
              .toss();
          })
          .toss();
      })
      .toss();
  })
  .toss();

test.create('Get session info from couchdb')
  .get('http://sessiontf.local:1337/_session')
  .expectStatus(200)
  .expectJSON({
    userCtx:{
      name:null
    }
  })
  .expectJSONTypes({
    authenticator:Object
  })
  .toss();
test.create('Get session info from couchdb with basic auth')
  .get('http://sessiontf.local:1337/_session')
  .auth('alice','whiterabbit')
  .expectStatus(200)
  .expectJSON({
    userCtx:{
      name:'alice'
    }
  })
  .expectJSONTypes({
    authenticator:Object
  })
  .toss();
test.create('Create session, get info from couchdb')
  .post('http://sessiontf.local:1337/_session', {name:'alice', password:'whiterabbit'})
  .expectStatus(200)
  .expectJSON({ok:true})
  .after(function(error,resource) {
    test.create('Get session info from couchdb with cookie auth')
      .get('http://sessiontf.local:1337/_session')
      .addHeader("Cookie",resource.headers['set-cookie'])
      .expectStatus(200)
      .expectJSON({
        userCtx:{
          name:'alice'
        }
      })
      .expectJSONTypes({
        authenticator:Object
      })
      .toss();
  })
  .toss();
test.create('Get session info from proxy')
  .get('http://sessionff.local:1337/_session')
  .expectStatus(200)
  .expectJSON({
    name:null
  })
  .expectJSONTypes({
    authenticator:Object
  })
  .toss();
test.create('Get session info from proxy with basic auth')
  .get('http://sessionff.local:1337/_session')
  .auth('alice','whiterabbit')
  .expectStatus(200)
  .expectJSON({
    name:'alice'
  })
  .expectJSONTypes({
    authenticator:Object
  })
  .toss();
test.create('Get session info from proxy with cookie auth')
  .post('http://sessionff.local:1337/_session', {name:'alice', password:'whiterabbit'})
  .expectStatus(200)
  .expectJSON({ok:true})
  .after(function(error,resource) {
    test.create('Get session info from proxy with cookie auth')
      .get('http://sessionff.local:1337/_session')
      .addHeader("Cookie",resource.headers['set-cookie'])
      .expectStatus(200)
      .expectJSON({
        name:'alice'
      })
      .expectJSONTypes({
        authenticator:Object
      })
      .toss();
  })
  .toss();
test.create('Get session info from proxy with basic auth')
  .get('http://sessionft.local:1337/_session')
  .auth('carroll','curiouser')
  .expectStatus(200)
  .expectJSON({
    name:'carroll'
  })
  .expectJSONTypes({
    authenticator:Object
  })
  .toss();
test.create('Get session info from proxy with cookie auth')
  .post('http://sessionft.local:1337/_session', {name:'carroll', password:'curiouser'})
  .expectStatus(200)
  .expectJSON({ok:true})
  .after(function(error,resource) {
    test.create('Get session info from proxy with cookie auth')
      .get('http://sessionft.local:1337/_session')
      .addHeader("Cookie",resource.headers['set-cookie'])
      .expectStatus(200)
      .expectJSON({
        name:'carroll'
      })
      .expectJSONTypes({
        authenticator:Object
      })
      .toss();
  })
  .toss();
