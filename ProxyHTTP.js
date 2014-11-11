var http = require('http');
var fs = require('fs');
var ldap = require('ldapjs');
var url = require('url');
var crypto = require ('crypto');

function isFunction(fun) { return typeof fun == "function";}
var conf={};

if (fs.existsSync('config.js')) {
  conf = require("./config");
  var servers=conf.servers;
  var port=conf.port;
  conf=servers;
}
if (fs.existsSync('config.json')) {
  // Reading of the main configuration file : config.json
  conf = JSON.parse(
    fs.readFileSync('config.json', 'utf8')
  );
  var port=1337;
}

if (!conf || !port) {
  console.log("please configure the reverse Proxy correctly");
  process.exit(1);
}

// Function that write the log inside the file related to right server

var log = function (context, err, code){
  var remoteIP=context.req.headers["x-forwarded-for"] || context.req.connection.remoteAddress;;
  var rule='??';
  var logFile="ProxyHTTP.log";
  if ('conf' in context) {
    var thisConf=conf[context.conf];
    if ('logFile' in thisConf) logFile=thisConf.logFile;
    rule=context.conf+'/';
    if ('ruleNo' in context) {
      rule+=context.ruleNo;
    } else {
      rule+='##';
    }
  }
  rule='['+rule+']';
    if (err == "HTTP" && context.login)var data = "" + context.date + "\t" + remoteIP + "\t" + context.login + "\t" + context.req.method + "\t" + context.req.headers.host +context.req.url + "\t" + code +"\t"+rule;

    else if (context.restricted) var data = "" + context.date + "\t" + remoteIP + "\t" + err;
    else if (err == "HTTP")var data = "" + context.date + "\t" + remoteIP + "\t" + context.req.method + "\t" + context.req.headers.host + context.req.url + "\t" + code +"\t"+rule;
  
  if (data){
    console.log(data);
    if (logFile) fs.appendFileSync(logFile, data+"\n");
    //else fs.appendFileSync("ProxyHTTP.log", data+"\n"); //change the name of the proxy log file inside the code
  };
};

// Test function for basic http authentication with a fixed login/password defined in config.json

var authentifyDummy =function (context, callback){
  
  context.restricted = true;

  if(!context.req.headers.authorization){
    context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
    sendResponse(context,401);
  }else{
    if(context.login === conf[context.conf].authData.login && context.pw === conf[context.conf].authData.pw){
      callback();
    }else{
      context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
      sendResponse(context,401);
    }
  }
}

// Cache of recent LDAP bind informations

var servLDAP = {};

// Function that remove old cached informations about LDAP bind

var flush = function(id, server){
  console.log("flushing ldap auth "+id+" from server "+server);
  delete servLDAP[server][id];
  if (servLDAP[server] === {}) delete servLDAP[server];
};

// LDAP bind with HTTP basic authentication

var loginLDAP = function (context, callback) {
  var negativeCacheTime=(conf[context.conf].ldap.negativeCacheTime || 300) /* 5 minutes*/ * 1000 /*ms*/;
  var positiveCacheTime=(conf[context.conf].ldap.positiveCacheTime || 900) /* 15 minutes*/ * 1000 /*ms*/;

  var url=conf[context.conf].ldap.url;
  var ldapReq=conf[context.conf].ldap.id+ context.login +','+conf[context.conf].ldap.cn; //do not manage more than one dc information
  var id=crypto.createHash('sha1').update(url).update(ldapReq).update(context.pw).digest('hex');
  var login=context.login;
  if (typeof conf[context.conf].ldap.domain != "undefined") {
    var domain= conf[context.conf].ldap.domain;
    if (domain && typeof domain == "string") {
      domain=conf[context.conf].ldap.domain;
    } else {
      domain=require("url").parse(url).host;
    }
    if (domain)
      login=context.login+"@"+domain;
  }
  if (!servLDAP[url] || !servLDAP[url][id]){
    console.log("logging in "+ldapReq+" into "+url);

    if (!servLDAP[url]) {
	servLDAP[url] ={};
    }
    if (!(id in servLDAP[url])) {
      servLDAP[url][id]={};
    }

    var serveursLDAP=ldap.createClient({
      'url' : url
    });

    serveursLDAP.bind(ldapReq, context.pw, function(err) {
      if ("timeOut" in servLDAP[url][id]) {
	clearTimeout(servLDAP[url][id].timeOut);
      }

      servLDAP[url][id].err = err;
      servLDAP[url][id].timeOut=setTimeout(flush, err?negativeCacheTime:positiveCacheTime, id, url);
      if (!err) {
	console.log("authentified!");
	context.login=login;
	serveursLDAP.unbind(function () {
	  serveursLDAP.socket.destroy();
	  callback(err);
	});
      } else {
	console.log("LDAP error : " + JSON.stringify(err));
	callback(err);
	serveursLDAP.socket.destroy();
      }
    });
  }else{
    if (!servLDAP[url][id].err) context.login=login;
    callback(servLDAP[url][id].err);
  }

  function setLogin(context) {
    
  }
}

var authentifyLDAP =function (context, callback, callbackOnError){

  callbackOnError=callbackOnError || false;

  context.restricted = true;

  if(!context.req.headers.authorization){
    context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
    sendResponse(context,401);
  }else{

      loginLDAP( context, function(err) {
	  if (!err) {
	    callback(err);
 	  } else {
	    if (!callbackOnError) {
	      log(context, err, 0);
	      context.res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
	      sendResponse(context,401);
	    } else {
	      callback(err);
	    }
	  }
      });
  }
}

var sendResponse=function(context,statusCode,message) {
  context.res.statusCode = statusCode;
  log(context, "HTTP", statusCode);
  context.res.end(message);
}
// Function that manage the authorization to access to specific resources defined inside config.json

var AuthorizList =function (context, callback){

  context.restricted = true;

  var idDoc = context.req.url.split('/')[3];
  if(conf[context.conf].restricted[idDoc]){
    if (conf[context.conf].restricted[idDoc].indexOf(context.login) == -1){
      sendResponse(context,403,"Forbidden");
    } else callback();
  }else{
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

function couchDBHeaders(nodeHeaders) {
  var couchHeaders={};
  for (var i in nodeHeaders) {
    couchHeaders[uCaseHeader(i)]=nodeHeaders[i];
  }
  return couchHeaders;
}

// Main proxy function that forward the request and the related answers

var proxyWork = function(context, callback){
   if (!context.req.readable) {
     if (context.options.body && typeof context.options.body =='string') context.options.headers['content-length']=context.options.body.length;
     else delete context.options.headers['content-length'];
   }
   var proxyReq = http.request(context.options, function (res){
    if (res.headers.location && conf[context.conf].rewritePath.enable){
      var splitHeaders = res.headers.location.split('/');
      res.headers.location = context.req.headers.origin;
      for (var i = (3 + conf[context.conf].rewritePath.headersOffset); i < splitHeaders.length; i++) {
        res.headers.location = res.headers.location +'/'+ splitHeaders[i];
      }
    }

    var headers=res.headers;
    if ('rawHeaders' in res) { //this is true for node.js >=0.11.6
      headers=res.rawHeaders;
    } else if (conf[context.conf].couchDBCompat) {
      headers=couchDBHeaders(headers);
    }

    context.res.writeHead(res.statusCode, headers);
    log(context, "HTTP", res.statusCode);
    res.on('data',function(chunkOrigin) {
        context.res.write(chunkOrigin);
    });
    res.on('end', function(){
      context.res.end();
      res.socket.destroy();
      isFunction(callback) && callback();
    });
  });

  proxyReq.on('error', function(err){
    console.log('problem with the server: ' + JSON.stringify(err));
    sendResponse(context,504,"Gateway Timeout");
  });

  if (context.req.readable) {

  context.req.on('data', function(chunkInit){
    proxyReq.write(chunkInit)
  });

  context.req.on('error', function(err) {
    log(context, err, 0);
    console.log('problem with request: ' + err.message);
  });

  context.req.on('end', function(){
    proxyReq.end();
  });
  } else {
    if (context.options.body) proxyReq.write(context.options.body);
    proxyReq.end();
  }
}

// Function that allow to find the index of the requested server inside config.json

var matching = function(host){ 
  var verif = false;
  var i =0;
  while ((verif == false) && (i < conf.length)){
    var re = new RegExp(conf[i].hostProxy, "i");
    verif = re.test(host);
    if (!verif) {
      var re = new RegExp(conf[i].hostProxy+":"+port, "i");
      verif = re.test(host);
    }
    if (verif == false)i++;
  };
  if (verif == false ) i = -1;
  return i;
};

// Main HTTP server

http.createServer(function (request, response){
  var context = {
    "req": request,
    "res": response,
    "date": new Date(),
    log: log,
    sendResponse: sendResponse,
    proxyWork: proxyWork,
    AuthorizList: AuthorizList,
    authentifyLDAP: authentifyLDAP,
    loginLDAP: loginLDAP,
    authentifyDummy: authentifyDummy,
    couchDBHeaders: couchDBHeaders
  };

  var domain=require("domain").create();
  domain.on("uncaughtException",function(err) {
    console.log("BIG UNCAUGHT EXCEPTION");
    console.log(err);
    console.log(err.stack);
    sendResponse(context,500,"Server Exception ");
  });
  domain.on("error",function(err) {
    console.log("BIG ERROR");
    console.log(err);
    console.log(err.stack);
    sendResponse(context,500,"Server Error ");
  });

  domain.add(request);
  domain.add(response);

  domain.run(function() {

  var index = matching(request.headers.host);
  if(index == -1){
    sendResponse(context,404,"Not Found");
  }else{
  	context.conf = index;
    
    var head = JSON.parse(JSON.stringify(request.headers)); 
    if (request.headers.authorization && conf[index].hideAuth) delete head.authorization;
    if (!conf[index].preserveHost) delete head.host;
    
    var options = {
      'host': conf[index].host,
      'port': conf[index].port, 
      'path': conf[index].path + url.parse(request.url).path,
      'method': request.method,
      'headers': head,
      'agent': false
    };

    context.options = options;

    if (request.headers.authorization){
      context.auth = request.headers.authorization.split(" ")[1];
      context.login = new Buffer(context.auth, 'base64').toString().split(':')[0];
      context.pw = new Buffer(context.auth, 'base64').toString().split(':')[1];
    };

    var i=0;
    var found=false;
    while(i<conf[index].rules.length && !found){
      try {
	var control=conf[index].rules[i].control;
	var action=conf[index].rules[i].action;
	var test=false;
	if(isFunction(control)) test=control(context);
	else if (typeof control == "string") test=eval(control);
	if (test) {
	  context.ruleNo=i;
	  if (isFunction(action)){
	    action(context);
	  } else {
	    eval(action);
	  }
	  if (conf[index].rules[i].final) {
	    found = true;
	  }
	}
      } catch(e) {
	console.log(e.stack);
	sendResponse(context,500,"Server Exception "+index+"/"+i);
	found=true;
      }
      i++;
    }
    if (!found) {
      proxyWork(context);
    }
  }
  });
}).listen(port); // port has to be changed directly inside the code. 
console.log('Server running port '+port);
