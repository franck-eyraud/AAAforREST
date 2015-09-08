var express = require('express');
var vhost = require('vhost');
var proxy = require('express-http-proxy');
var bodyParser = require('body-parser');
var session = require('express-session');
var http = require('http');
var url = require('url');
var async = require('async');
var configuration = require('./configuration');
var ldap = require('./authenticator.ldap');
var basic = require('./authenticator.http');
var cookie = require('./authenticator.cookie');
var log = require('./accounter.log');
var forwardAuth = require('couch-proxy-auth');

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
 * Return true if the login was found.
 * Set `auth.success` to true if the credentials were good.
 */
var dummy = function(auth, settings, callback) {
  if (auth.login==settings.login) {
    auth.success = auth.password==settings.password;
  }
  callback(auth.success!==undefined);
};

function authenticateIfPresent(context, callback) {
  var request = context.requestIn;
  authenticate(context, callback, request.auth===undefined);
}

function authenticate(context, callback, shouldNotCatch) {
    var request = context.requestIn;
    var site = configuration.site(request);
    var authenticators = site.authentication;
    async.detectSeries(authenticators, function(authenticator, callback) {
      if (request.auth) {
        if (authenticator.dn) {
          ldap(request.auth, authenticator, callback);
        } else if (authenticator.url) {
          basic(request.auth, authenticator, callback);
        } else {
          dummy(request.auth, authenticator, callback);
        }
      } else if (context.requestIn.headers.cookie) {
        cookie.check(context, authenticator, callback);
      } else {
        callback();
      }
    }, function(authenticator) {
      if (request.auth && request.auth.success) {
        if (site.forwardedLoginHeader) {
          context.options.headers[site.forwardedLoginHeader] = request.auth.login;
        }
        if (site.forwardedLoginSecret) {
          var addedHeaders = forwardAuth(
            request.auth.login,
            site.forwardedLoginRoles || 'protect',
            site.forwardedLoginSecret
          );
          for (var newHeader in addedHeaders) {
            // since roles are forced to a value, the role header is given by couch-proxy-auth
            // so can't be forged
            removeHeader(context.options.headers,newHeader);
            context.options.headers[newHeader] = addedHeaders[newHeader];
          }
        }
        callback(true);
      } else {
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
  var request = context.requestIn;
  var acl = configuration.site(request).restricted;
  var resourceMatch, userMatch;
  for (var uriPart in acl) {
    resourceMatch = context.requestIn.url.indexOf(uriPart) > -1;
    userMatch =  acl[uriPart].indexOf(request.auth.login) > -1;
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
  var request = context.requestIn;
  var site = configuration.site(request);
  if (!context.requestIn.readable) {
    if (context.options.body && typeof context.options.body =='string')
      context.options.headers['Content-Length']=context.options.body.length;
    else
      delete context.options.headers['Content-Length'];
  }

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

function parseHttpCredentials(context) {
  var request = context.requestIn;
  var authorization = request.headers.authorization;
  if (authorization) {
    var token = authorization.split(" ");
    if (token[0]=='Basic' && token.length>1) {
      var credentials = new Buffer(token[1], 'base64').toString().split(':');
      request.auth = {
        login: credentials[0],
        password: credentials.length>1 ? credentials[1] : ""
      };
    }
  }
}

/**
 * @implement Express middleware.
 */
function parseFormAuthentication(request, response, next) {
  if (!request.auth) {
    var form = request.body;
    if (form.name && form.password) {
      request.auth = {
        login: form.name,
        password: form.password
      };
    }
  }
  next();
}

/**
 * @implement Express middleware.
 */
function checkCookieAuthentication(request, response, next) {
  if (!request.auth && request.session && request.session.login) {
    request.auth = {
      login: request.session.login,
      success: true
    };
  }
  next();
}

/**
 * @implement Express middleware.
 */
function continueIfAuthentified(request, response, next) {
  if (request.auth && request.auth.success) {
    next();
  } else {
    response.sendStatus(401);
  }
}

function ok(request, response, next) {
  var o = {ok: true};
  if (request.auth) {
    o.name = request.auth.login;
  }
  response.json(o);
}

/**
 * @return middleware that checks login and password against
 * a single HTTP URI with basic authentication.
 */
function checkAuthenticationOnHTTP(authenticator) {
  return function(request, response, next) {
    if (request.auth) {
      basic(request.auth, authenticator, function() {
        next();
      });
    } else {
      next();
    }
  };
}

/**
 * @return middleware that checks login and password against
 * an LDAP directory.
 */
function checkAuthenticationOnLDAP(authenticator) {
  return function(request, response, next) {
    if (request.auth) {
      ldap(request.auth, authenticator, function() {
        next();
      });
    } else {
      next();
    }
  };
}

/**
 * @return middleware that checks login and password against
 * a given login and password
 */
function checkAuthenticationOnFixed(authenticator) {
  return function(request, response, next) {
    if (request.auth) {
      dummy(request.auth, authenticator, function(authentified) {
        next();
      });
    } else {
      next();
    }
  };
}

/**
 * @return middleware that checks login and password against
 * the authenticator according to its type.
 */
function checkAuthentication(authenticator) {
  if (authenticator.dn)
    return checkAuthenticationOnLDAP(authenticator);
  if (authenticator.url)
    return checkAuthenticationOnHTTP(authenticator);
  return checkAuthenticationOnFixed(authenticator);
}

var setSession = session({
  secret: 's3cr3t'+ new Date(),
  resave: false,
  saveUninitialized: false,
  unset: 'destroy',
  cookie: {
    domain: configuration.domain
  }
});

function setSessionLogin(request, response, next) {
  request.session.login = request.auth.login;
  next();
}

function unsetSessionLogin(request, response, next) {
  request.session = null;
  request.auth = null;
  next();
}

function continueIfForm(request, response, next) {
  var type = request.headers['content-type'];
  if (!type || type.indexOf('application/x-www-form-urlencode')!==0) {
    return response.sendStatus(415);
  }
  next();
}

var userApp = express.Router();
userApp.use(express.static('public'));
userApp.route('/_users/*').all(
  proxy(configuration.users || 'localhost:5984')
);
userApp.route('/_session')
  .post(
    unsetSessionLogin,
    continueIfForm,
    bodyParser.urlencoded({extended: false}),
    parseFormAuthentication,
    checkAuthentication(configuration.authentication), //TODO multiple sources
    continueIfAuthentified,
    setSession,
    setSessionLogin,
    ok
  ).get(
    setSession,
    checkCookieAuthentication,
    ok
  ).delete(
    setSession,
    checkCookieAuthentication,
    unsetSessionLogin,
    ok
  );

var app = express();
app.use(vhost('auth.*', userApp));

app.use(function(requestIn, responseOut, next) {
  var context = {
    requestIn: requestIn,
    responseOut: responseOut
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

  var site = configuration.site(requestIn);
  if (site===null) {
    sendResponse(context, 404, "Not Found");
  } else {
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
