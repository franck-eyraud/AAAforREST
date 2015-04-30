module.exports = function() {

  var LDAP = require('ldapjs');
  var CRYPTO = require ('crypto');
  var URL = require('url');

  var cache = {};

  var flush = function(id, server) {
    console.log('flushing ldap auth ' + id + ' from server ' + server);
    delete cache[server][id];
    if (cache[server] === {}) delete cache[server];
  };

  return function(context, settings, callback) {
    if (!context.login) return callback(false);
    var negativeCacheTime = (settings.negativeCacheTime || 300) /* 5 minutes*/ * 1000 /*ms*/;
    var positiveCacheTime = (settings.positiveCacheTime || 900) /* 15 minutes*/ * 1000 /*ms*/;
    var url = settings.url;
    var ldapReq = settings.id + '=' + context.login + ',' + settings.dn; //do not manage more than one dc information
    var id = CRYPTO.createHash('sha1')
      .update(url).update(ldapReq).update(context.pw||"")
      .digest('hex');
    var login = context.login;
    if (typeof settings.domain != 'undefined') {
      var domain = settings.domain;
      if (domain && typeof domain == 'string') {
        domain = settings.domain;
      } else {
        domain = URL.parse(url).host;
      }
      if (domain)
        login = context.login + '@' + domain;
    }

    var maxWaits=20;
    var waits=0;

    checkAuth();

    function checkAuth() {
      if (!cache[url] || !cache[url][id]) {
        console.log('Logging in ' + ldapReq + ' into ' + url);
        if (!cache[url]) {
          cache[url] = {};
        }
        if (!(id in cache[url])) {
          cache[url][id] = {};
        }
        var ldap = LDAP.createClient({
          'url': url
        });
        ldap.bind(ldapReq, context.pw, function(err) {
          if ('timeOut' in cache[url][id]) {
            clearTimeout(cache[url][id].timeOut);
          }
          cache[url][id].err = err;
          cache[url][id].timeOut =
            setTimeout(flush, err?negativeCacheTime:positiveCacheTime, id, url);
          var isAuthentified = !err;
          if (isAuthentified) {
            context.login = login;
            ldap.unbind(function () {
              callback(isAuthentified);
            });
          } else {
            console.log('LDAP error: ' + JSON.stringify(err));
            callback(isAuthentified);
          }
        });
      } else {
        if (cache[url][id].hasOwnProperty("err")) {
          if (!cache[url][id].err) context.login = login;
          callback(!cache[url][id].err);
        } else {
           waits++;
           if (waits>maxWaits) {
             delete cache[url][id];
             waits=0;
             checkAuth();
           } else {
             setTimeout(checkAuth,100);
           }
        }
      }
    }
  };

}();
