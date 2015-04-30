module.exports = function() {

  var http = require('http');
  var url = require('url');

  return function(context, settings, callback) {
    var service = url.parse(settings.url);
    http.get({
      hostname: service.hostname,
      port: service.port || 80,
      path: service.path,
      auth: context.login + ':' + context.pw
    }, function(response) {
      callback(response.statusCode=='200');
    });
  }

}();
