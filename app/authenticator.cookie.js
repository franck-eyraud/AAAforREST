var crypto=require('crypto');
var Cookies=require('cookies');

function readBody(context,callback) {
  if (context.requestIn.readable) {
    var body="";
    context.requestIn.on('data',function(chunk) {
      body+=chunk;
    });
    context.requestIn.on('end',function() {
      context.options.body=body;
      callback(body);
    });
  } else {
    callback(context.options.body);
  }
}

function parseBody(context,sessionHandler) {
  var post=require("querystring").parse(context.options.body);
  var userfield=sessionHandler.userfield || "name";
  var passfield=sessionHandler.passfield || "password";
  context.login=post[userfield] || "";
  context.pw=post[passfield] || "";
};

function handleSessionRequest(sessionHandler) {
  var $=this;
  var context=this.context;
  switch (this.method) {
    case "POST":
      readBody(this.context,function(body) {
        parseBody($.context,sessionHandler);
        ignoreCookie($.context,sessionHandler);
        $.authenticate($.context,function(authenticator) {
          if (authenticator) {
            setAuthCookie($.context,sessionHandler);
            if (sessionHandler.forward) {
              delete context.options.body;
              $.context.options.method="GET";
              $.proxyWork($.context);
            } else {
              $.sendResponse($.context, 200, JSON.stringify({ok: true}));
            }
          } else {
            setAuthCookie($.context,sessionHandler);
            if(sessionHandler.forward) {
              if (!sessionHandler.preserveCredentials)
                delete context.options.body;
              $.proxyWork($.context);
            } else {
              $.sendResponse($.context, 401, JSON.stringify({error: "unauthorized"}));
            }
          }
        },true);
      });
      break;
    case "DELETE":
      delete $.context.login;
      setAuthCookie($.context,sessionHandler);
      if (sessionHandler.forward) {
        $.proxyWork($.context);
      } else {
        $.sendResponse($.context, 200, 'Logged out');
      }
      break;
    case "GET":
      $.authenticateIfPresent($.context,function(authenticator) {
        if (sessionHandler.forward) {
          $.proxyWork($.context);
        } else {
          var session={
            name:$.context.login || null,
            authenticator:authenticator
          }
          $.sendResponse($.context, 200, JSON.stringify(session));
        }
      });
      break;
    default:
      if (sessionHandler.forward) {
        $.authenticateIfPresent($.context,function() {
          proxyWork($.context);
        });
      } else {
        $.sendResponse($.context, 405, 'Method not allowed');
      }
  }
}

function addSessionRule(site) {
  if (site.sessionHandler) {
    if (!site.sessionHandler.hasOwnProperty("preserveCredentials")) {
      site.sessionHandler.preserveCredentials=site.preserveCredentials;
    }
    if (!site.sessionHandler.hasOwnProperty("forward")) {
      site.sessionHandler.forward=site.sessionHandler.preserveCredentials;
    }
    var rule={};
    rule.control=function() {
      var active=true;
      if (!site.sessionHandler.path) {
        console.log("session handler with no Path defined");
        return false;
      } else if (!/^\//.test(site.sessionHandler.path)) {
        site.sessionHandler.path = "/" +site.sessionHandler.path;
      }
      return new RegExp("^"+site.sessionHandler.path).test(this.path);
    };
    rule.action=function() {
      handleSessionRequest.call(this,site.sessionHandler);
    };
    site.rules.unshift(rule);

    var authenticator={
      cookieName:site.sessionHandler.cookieName||null,
    };
    site.authentication=site.authentication || [];
    site.authentication.unshift(authenticator);
  }
}

var saved_cookies={};
const default_cookie_auth_name='AAAforRest-auth';
var defaultExpiryTime=600000;

function ignoreCookie(context,authenticator) {
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  context.cookie=context.cookie||{};
  context.cookie.ignore=context.cookie.ignore || [];
  context.cookie.ignore.push(authenticator.cookieName);
}

function checkAuthCookie(context,authenticator,callback) {
  var currcookie;
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  if (context.login || context.cookie && context.cookie.ignore
    && context.cookie.ignore.indexOf(authenticator.cookieName) !=-1) {
    return callback(false);
  }
  var expiryTime=authenticator.sessionLength || defaultExpiryTime;
  var cookies=new Cookies(context.requestIn,context.responseOut);
  if (currcookie=cookies.get(authenticator.cookieName)) {
    var auth_info;
    if (auth_info=saved_cookies[currcookie]) {
      if (auth_info.timestamp<new Date().getTime()+expiryTime && auth_info.login) {
        auth_info.timestamp=new Date();
        context.login=auth_info.login;
        console.log("authenticating "+context.login+" through cookie "+currcookie);
        return callback(true);
      } else {
        console.log("expired");
        delete saved_cookies[currcookie];
      }
    } else {
      console.log("cookie does not exist");
      cookies.set(authenticator.cookieName,null,{overwrite:true});
    }
  }
  callback(false);
}

function setAuthCookie(context,authenticator) {
  var currcookie;
  authenticator.cookieName=authenticator.cookieName || default_cookie_auth_name;
  var expiryTime=authenticator.sessionLength || defaultExpiryTime;
  var cookies=new Cookies(context.requestIn,context.responseOut);
  if (currcookie=cookies.get(authenticator.cookieName)) {
    if (auth_info=saved_cookies[currcookie]) {
      if (context.login && auth_info.login!=context.login) {
        console.log("switching authentication from "+auth_info.login
            +" to "+context.login);
      }
    } else {
      auth_info={};
    }
    auth_info.timestamp=new Date().getTime();
  } else if (context.login) {
    var ok=false;
    while (!ok) {
      currcookie=crypto.createHash('sha1').update(authenticator.cookieName).update("plipplop"+new Date().getTime()).digest('hex');
      console.log(currcookie);
      if (!saved_cookies[currcookie]) ok=true;
    }
    console.log("new session "+currcookie);
    auth_info={timestamp:new Date().getTime()}
  }
  if (context.login) {
    console.log("authenticating "+context.login);
    auth_info.login=context.login;
    saved_cookies[currcookie]=auth_info;
  } else {
    if (currcookie) {
      delete saved_cookies[currcookie];
      currcookie=null;
    } else {
      return;
    }
  }
  console.log("setting cookie "+currcookie);
  cookies.set(authenticator.cookieName,currcookie,{overwrite:true});
}

module.exports={
  check: checkAuthCookie,
  manageSession:addSessionRule
}

