'use strict';

var helpers = require('./helpers');
var btoa = require('btoa'); // jshint ignore:line
var uuid = require('node-uuid');
var oauth = require('oauth-sign');
var createHmac = require('create-hmac');
var createHash = require('create-hash');
var CookieJar = require('cookiejar').CookieJar;
var _ = {
  each: require('lodash-compat/collection/each'),
  includes: require('lodash-compat/collection/includes'),
  isObject: require('lodash-compat/lang/isObject'),
  isArray: require('lodash-compat/lang/isArray')
};

/**
 * SwaggerAuthorizations applies the correct authorization to an operation being executed
 */
var SwaggerAuthorizations = module.exports.SwaggerAuthorizations = function (authz) {
  this.authz = authz || {};
};

/**
 * Add auths to the hash
 * Will overwrite any existing
 *
 */
SwaggerAuthorizations.prototype.add = function (name, auth) {
  if(_.isObject(name)) {
    for (var key in name) {
      this.authz[key] = name[key];
    }
  } else if(typeof name === 'string' ){
    this.authz[name] = auth;
  }

  return auth;
};

SwaggerAuthorizations.prototype.remove = function (name) {
  return delete this.authz[name];
};

SwaggerAuthorizations.prototype.apply = function (obj, securities) {
  var status = true;
  var applyAll = !securities;
  var flattenedSecurities = [];

  // favor the object-level authorizations over global
  var authz = obj.clientAuthorizations || this.authz;

  // Securities could be [ {} ]
  _.each(securities, function (obj, key) {

    // Make sure we account for securities being [ str ]
    if(typeof key === 'string') {
      flattenedSecurities.push(key);
    }

    // Flatten keys in to our array
    _.each(obj, function (val, key) {
      flattenedSecurities.push(key);
    });
  });

  _.each(authz, function (auth, authName) {
    if(applyAll || _.includes(flattenedSecurities, authName)) {
      var newStatus = auth.apply(obj);
      status = status && !!newStatus; // logical ORs regarding status
    }
  });

  return status;
};

/**
 * ApiKeyAuthorization allows a query param or header to be injected
 */
var ApiKeyAuthorization = module.exports.ApiKeyAuthorization = function (name, value, type) {
  this.name = name;
  this.value = value;
  this.type = type;
};

ApiKeyAuthorization.prototype.apply = function (obj) {
  if (this.type === 'query') {
    // see if already applied.  If so, don't do it again

    var qp;
    if (obj.url.indexOf('?') > 0) {
      qp = obj.url.substring(obj.url.indexOf('?') + 1);
      var parts = qp.split('&');
      if(parts && parts.length > 0) {
        for(var i = 0; i < parts.length; i++) {
          var kv = parts[i].split('=');
          if(kv && kv.length > 0) {
            if (kv[0] === this.name) {
              // skip it
              return false;
            }
          }
        }
      }
    }

    if (obj.url.indexOf('?') > 0) {
      obj.url = obj.url + '&' + this.name + '=' + this.value;
    } else {
      obj.url = obj.url + '?' + this.name + '=' + this.value;
    }

    return true;
  } else if (this.type === 'header') {
    if(typeof obj.headers[this.name] === 'undefined') {
      obj.headers[this.name] = this.value;
    }

    return true;
  }
};

var CookieAuthorization = module.exports.CookieAuthorization = function (cookie) {
  this.cookie = cookie;
};

CookieAuthorization.prototype.apply = function (obj) {
  obj.cookieJar = obj.cookieJar || new CookieJar();
  obj.cookieJar.setCookie(this.cookie);

  return true;
};

/**
 * Password Authorization is a basic auth implementation
 */
var PasswordAuthorization = module.exports.PasswordAuthorization = function (username, password) {
  if (arguments.length === 3) {
    helpers.log('PasswordAuthorization: the \'name\' argument has been removed, pass only username and password');
    username = arguments[1];
    password = arguments[2];
  }
  this.username = username;
  this.password = password;
};

PasswordAuthorization.prototype.apply = function (obj) {
  if(typeof obj.headers.Authorization === 'undefined') {
    obj.headers.Authorization = 'Basic ' + btoa(this.username + ':' + this.password);
  }

  return true;
};

/**
 * OAuth1 Authorization is an OAuth 1 implementation
 */

var Oauth1Authorization = module.exports.Oauth1Authorization = function (username, password, method) {
  this.username = username;
  this.password = password;
  this.method = method;
};

Oauth1Authorization.prototype.apply = function (obj) {
  if (!obj.hasOwnProperty('clientAuthorizations')) {
    return true;
  }

  var init = function init(url, method, key) {
    var oauthparams = {
      "oauth_consumer_key" : key,
      "oauth_signature_method" : method,
      "oauth_nonce" : uuid().replace(/-/g, ''),
      "oauth_timestamp" : Math.floor( Date.now() / 1000 ).toString(),
      "oauth_version" : '1.0'
    };
    switch (method) {
      case 'HMAC-SHA1':
        method ='sha1';
        break;
      case 'HMAC-SHA256':
        method = 'sha256';
        break;
    }
    var params = {};
    var tmp = url.split('?');
    if (tmp.length > 1) {
      var queryparams = tmp[1].split('&');
      for (var i = 0; i < queryparams.length; i++) {
        var param = queryparams[i].split('=');
        var value = '';
        if (param.length > 1) {
          value = param[1];
        }
        params[decodeURIComponent(param[0])] = decodeURIComponent(value);
      }
    }
    return { 'url': tmp[0], 'method': method, 'params': params, 'oauth': oauthparams};
  };

  if(obj.headers && obj.headers['Content-Type'] && (obj.headers['Content-Type'] === 'application/x-www-form-urlencoded')) {
    if(obj.body && (obj.body.indexOf('oauth_signature') === -1)) {
      if (!this.signature) {
        var init = init(obj.url, this.method, this.username);
        var data = [];
        var arr = obj.body.split('&');
        for (var i = 0; i < arr.length; i++) {
          var split = arr[i].split('=');
          var value = '';
          if (arr.length > 1) {
            value = split[1].trim();
          }
          data[split[0].trim()] = value;
        }
        init.oauth['oauth_callback'] = 'about:blank';
        for (var key in init.oauth) {
          data[key] = init.oauth[key];
        }
        for (var key in data) {
          init.params[key] = data[key];
        }
        var querystring = Object.keys(init.params).sort().map(function(key){
            return escape(oauth.rfc3986(key)) + "%3D" + escape(oauth.rfc3986(init.params[key]))
        }).join('%26');
        var base = [obj.method, oauth.rfc3986(init.url), querystring].join('&');
        var key = [this.password, ''].map(oauth.rfc3986).join('&');
        data['oauth_signature'] = createHmac(init.method, key).update(base).digest('base64');
        var sig = '';
        for (var key in data) {
          sig = sig + '&' + encodeURIComponent(key) + '=' + encodeURIComponent(data[key]);
        }
        this.signature = sig;
      }
      obj.body = this.signature.substring(1);
    } else {
      this.signature = false;
    }
  } else if(typeof obj.headers.Authorization === 'undefined') {
    if (!this.signature) {
      if (typeof obj.body === 'undefined') {
          obj.body = '';
      }
      var init = init(obj.url, this.method, this.username);
      var hash = createHash(init.method).update(obj.body).digest('hex');
      init.oauth['oauth_body_hash'] = hash;
      for (var key in init.oauth) {
        init.params[key] = init.oauth[key];
      }
      var querystring = Object.keys(init.params).sort().map(function(key){
          return escape(oauth.rfc3986(key)) + "%3D" + escape(oauth.rfc3986(init.params[key]))
      }).join('%26');
      var base = [obj.method, oauth.rfc3986(init.url), querystring].join('&');
      var key = [this.password, ''].map(oauth.rfc3986).join('&');
      init.oauth['oauth_signature'] = createHmac(init.method, key).update(base).digest('base64');
      this.signature = 'OAuth ' +
        Object.keys(init.oauth).sort().map(function (i) {return i+'="'+oauth.rfc3986(init.oauth[i])+'"'}).join(',');

    }
    obj.headers.Authorization = this.signature;
  } else {
    this.signature = false;
  }

  return true;
};
