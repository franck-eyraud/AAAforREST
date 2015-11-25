var express = require('express');
var vhost = require('vhost');
var proxy = require('express-http-proxy');
var http = require('http');
var url = require('url');
var async = require('async');
var configuration = require('./configuration');
var ldap = require('./authenticator.ldap');
var basic = require('./authenticator.http');
var cookie = require('./authenticator.cookie');
var log = require('./accounter.log');

configuration.sites.forEach(cookie.manageSession);


function act(context, toDo) {
  var method = context.requestIn.method,
    path = url.parse(context.requestIn.url).path;
  var scope = {
    method: method,
    path: path,
    authenticate: authenticate,
    authenticateIfPresent: authenticateIfPresent,
    authorize: authorize,
    proxyWork: proxyWork,
    sendResponse: sendResponse,
    context: context
  };
  return typeof toDo == 'function' && toDo.call(scope) || eval(toDo);
}

function tryAgain(context) {
  context.responseOut.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
  sendResponse(context, 401, 'Unauthorized');
}

/*
 * Default implementation of checkCredentials (with fixed login and password)
 * that can be replaced for various authentication formats and protocols.
 */
var dummy = function(context, settings, callback) {
  callback(context.login && context.login==settings.login && context.pw==settings.password);
};

function authenticateIfPresent(context, callback) {
  var authenticationPresent=context.login ? true : false;
  authenticate(context,callback,!authenticationPresent);
};

function authenticate(context, callback, shouldNotCatch) {
    var authenticators = configuration.sites[context.conf].authentication;
    async.detectSeries(authenticators, function(authenticator, callback) {
      if (authenticator.url) {
        if (authenticator.dn) {
          ldap(context, authenticator, callback);
        } else {
          basic(context, authenticator, callback);
        }
      } else if (authenticator.hasOwnProperty("cookieName")) {
        cookie.check(context, authenticator, callback);
      } else {
        dummy(context, authenticator, callback);
      }
    }, function(successfulAuthenticator) {
      if (successfulAuthenticator) {
        if (!successfulAuthenticator.preserveCredentials) {
          delete context.options.headers.Authorization;
        }
        var site=configuration.sites[context.conf];
        if (site.forwardedLoginHeader && context.login) {
          context.options.headers[site.forwardedLoginHeader] = context.login;
        }
        if (site.forwardedLoginSecret && context.login) {
          var addedHeaders=require('couch-proxy-auth')(context.login,site.forwardedLoginRoles || 'protect',site.forwardedLoginSecret);
          for (var newHeader in addedHeaders) {
            // since roles are forced to a value, the role header is given by couch-proxy-auth
            // so can't be forged
            removeHeader(context.options.headers,newHeader);
            context.options.headers[newHeader] = addedHeaders[newHeader];
          }
        }
        callback(successfulAuthenticator);
      } else {
        delete context.login;
        //if authorization header is present, it means that preserveCredentials
        //is true, so we authorize to forward the request to upstream server
        if (context.options.headers.Authorization || shouldNotCatch) {
          callback();
        } else {
          tryAgain(context);
        }
      }
    });
}

function sendResponse(context, statusCode, message) {
  try {
    if (!context.responseOut.headersSent) {
      log(context, 'HTTP', statusCode);
      context.responseOut.status(statusCode).send(message);
    } else {
      console.log("trying to send status "+statusCode+" ("+message+") but headers already sent");
    }
  } catch (e) {
    console.log("exception sending status "+statusCode+" ("+message+") : "+e);
  } finally {
    context.responseOut.end();
  }
}

/**
 * Authorize access to restricted resources.
 */
function authorize(context, callback) {
  var acl = configuration.sites[context.conf].restricted;
  var resourceMatch, userMatch;
  for (var uriPart in acl) {
    resourceMatch = context.requestIn.url.indexOf(uriPart) > -1;
    userMatch =  acl[uriPart].indexOf(context.login) > -1;
    if (resourceMatch) break;
  }
  if (resourceMatch && !userMatch) {
    tryAgain(context);
  } else {
    callback();
  }
}

function uCaseWord(word) {
  switch(word) {
    case 'etag':return 'ETag';
    default: return word.replace(/^./,function(l){return l.toUpperCase();});
  }
}

function uCaseHeader(headerName) {
  return headerName.replace(/\w*/g,uCaseWord);
}

//TODO replace with `.rawHeaders` when Node.js stable version is 0.11
function preserveHeadersCase(nodeHeaders) {
  var couchHeaders={};
  for (var i in nodeHeaders) {
    couchHeaders[uCaseHeader(i)]=nodeHeaders[i];
  }
  return couchHeaders;
}

function removeHeader(headers,header) {
  for (var h in headers) {
    if (h.toLowerCase()==header.toLowerCase()) {
      delete headers[h];
    }
  }
}

function addHeaders(response,headers) {
  headers=preserveHeadersCase(headers);
  for (var header in headers) {
    var value=headers[header];
    var existingHeader=response.getHeader(header);
    if (existingHeader) {
      value=[value].concat(existingHeader);
    }
    response.setHeader(header,value);
  }
}

// Main proxy function that forward the request and the related answers

function proxyWork(context) {
  if (!context.requestIn.readable) {
    if (context.options.body && typeof context.options.body =='string')
      context.options.headers['Content-Length']=context.options.body.length;
    else
      delete context.options.headers['Content-Length'];
  }

  var site = configuration.sites[context.conf];

  function socketAbort(err) {
    console.log('error socket responseIn: ' + err.message);
    try {
      sendResponse(context,502,"Server closed socket");
      context.requestIn.socket.end();
    } catch (e) {
      console.log("caught this "+e+" which could happen if socket has been reused");
    }
  }

  var requestOut = http.request(context.options, function(responseIn) {
    try {
      if (responseIn.headers.location && site.hideLocationParts) {
        var locationParts = responseIn.headers.location.split('/');
        locationParts.splice(3, site.hideLocationParts);
        responseIn.headers.location = locationParts.join('/');
      }

      addHeaders(context.responseOut,responseIn.headers);

      try {
        log(context, 'HTTP', responseIn.statusCode);
      } catch (e) {
        console.log("cannot log "+responseIn.statusCode);
        console.log(e.stack);
      }
      context.responseOut.writeHead(
        responseIn.statusCode
      );
      responseIn.on('data', function(chunkOrigin) {
        context.responseOut.write(chunkOrigin);
      });
      responseIn.on('end', function() {
        context.responseOut.end();
        responseIn.socket.end();
        context.requestIn.socket.end();
      });

      responseIn.on('close', function() {
        console.log("close responseIn");
        context.responseOut.end();
      });

      responseIn.on("error",function(err) {
        console.log('problem with responseIn: ' + err.message);
        sendResponse(context,502,"Server closed socket");
      });

      responseIn.socket.on("error",socketAbort);
    } catch (e) {
      console.log("exception in proxyWork, aborting");
      console.log(e.stack);
      sendResponse(context,500,"Internal server error");
      requestOut.abort();
      context.requestIn.socket.end();
    }
  });

  requestOut.on('error', function(err){
    console.log('problem with requestOut: ' + JSON.stringify(err));
    sendResponse(context,502,"Server closed socket");
  });

  if (context.requestIn.readable) {

  context.requestIn.on('data', function(chunkInit) {
    requestOut.write(chunkInit);
  });

  context.requestIn.on('error', function(err) {
    console.log("error requestIn");
    console.log('problem with request: ' + err.message);
    sendResponse(context,400,err);
    requestOut.abort();
  });

  context.requestIn.on('end', function(){
    requestOut.end();
  });
  } else {
    if (context.options.body) requestOut.write(context.options.body);
    requestOut.end();
  }

  context.responseOut.on('close', function() {
    requestOut.abort();
    requestOut.socket.end();
  });

}

// Function that allow to find the index of the requested server inside config.json

var matching = function(host){
  var verif = false;
  var i =0;
  while ((verif == false) && (i < configuration.sites.length)){
    var site_host = configuration.sites[i].hostProxy;
    var re = new RegExp(site_host, "i");
    verif = re.test(host);
    if (!verif) {
      re = new RegExp(site_host + ":" + configuration.port, "i");
      verif = re.test(host);
    }
    if (verif == false)i++;
  }
  if (verif == false ) i = -1;
  return i;
};

function parseHttpCredentials(context) {
  var authorization = context.requestIn.headers.authorization;
  if (authorization) {
    var token = authorization.split(" ");
    if (token[0]=='Basic' && token.length>1) {
      var credentials = new Buffer(token[1], 'base64').toString().split(':');
      context.login = credentials.shift();
      context.pw = credentials.length>1 ? credentials.join(":") : "";
    }
  }
}

var userApp = express.Router();
userApp.use(express.static('public'));
userApp.route('/_users/*').all(proxy(configuration.users || 'localhost:5984'));

var app = express();
app.use(vhost('auth.*', userApp));

app.use(function(requestIn, responseOut, next) {
  var context = {
    requestIn: requestIn,
    responseOut: responseOut,
    date: new Date()
  };
  var domain=require("domain").create();
  domain.on("uncaughtException",function(err) {
    console.log("BIG UNCAUGHT EXCEPTION");
    console.log(err);
    console.log(err.stack);
    sendResponse(context, 500, "Server Exception");
  });
  domain.on("error",function(err) {
    console.log("domain error "+err);
    console.log(err.stack);
    sendResponse(context, 500, "Server Error");
  });

  domain.add(requestIn);
  domain.add(responseOut);

  domain.run(function() {

  var index = matching(requestIn.headers.host);
  if(index == -1){
    sendResponse(context, 404, "Not Found");
  }else{
    context.conf = index;
    var site = configuration.sites[index];
    context.options = {
      host: site.host || 'localhost',
      port: site.port || 80,
      path: (site.path || '') + url.parse(requestIn.url).path,
      method: requestIn.method,
      headers: preserveHeadersCase(requestIn.headers),
      agent: false
    };
    if (!site.preserveCredentials) delete context.options.headers.Authorization;
    parseHttpCredentials(context);
    var i = 0;
    var found = false;
    while (!found && i<site.rules.length) {
      var rule = site.rules[i];
      try {
        if (act(context, rule.control)===true) {
          found = true;
          act(context, rule.action);
        }
      } catch (e) {
        console.log(e + '. RULE ' + site.hostProxy + ' #' + i);
        sendResponse(context, 500, 'Configuration error');
      }
      i++;
    }
    if (!found) proxyWork(context); //Fallback rule
  }
  });
});

app.listen(configuration.port, function() {
  console.log('Server running port ' + configuration.port);
});
