var sys = require('sys'),
    querystring = require('querystring'),
    crypto = require('crypto'),
    urlparse = require('url').parse,
    errors = require('./oauth_error');

var OAuthServices = exports.OAuthServices = function(provider) {
    this.provider = provider;

    // Ensure the provider has the correct functions
    ['getConsumerByKey',
        'generateRequestToken',
        'generateAccessToken',
        'authorizeToken',
        'getTokenByKey',
        'validateNoReplay'].forEach(function(method) {
        if(method instanceof Function)
            throw Error("Data provider must provide the method "+method);
      });  
}

OAuthServices.prototype.verifySignature = function(params, request, callback) {
    var self = this;

    function finish_validation(consumer, token) {
        token = token || {};

        var calculatedSignature = self.calculateSignature(
            request, params, consumer.secret, token.token_secret);

        // Check if the signature is correct and return a request token
        if(calculatedSignature != params.oauth_signature) {
            callback(new errors.OAuthUnauthorizedError("Invalid signature"));
            return;
        }

        // Validate the timestamp and nonce values...
        self.provider.validateNoReplay(token, params.oauth_timestamp, params.oauth_nonce,
            function(err) {
                if(err)
                    callback(new errors.OAuthUnauthorizedError("Invalid timestamp/nonce"));
                else
                    callback(null, consumer, token);
        });
    }

    self.provider.getConsumerByKey(params.oauth_consumer_key,
        function(err, consumer) {
            if(err) {
                callback(err);
                return;
            }

            if(consumer.consumer_key == null || consumer.secret == null) {
                callback(new errors.OAuthProviderError(
                    "provider: getConsumerByKey must return an "+
                    "object with fields [consumer_key, secret]"));
                  return;
            }

            if(!params.oauth_token) {
                finish_validation(consumer);
            }
            else {
                // Retrieve the token secret as well...
                self.provider.getTokenByKey(params.oauth_token, function(err, token) {
                    if(err) {
                        callback(new errors.OAuthProviderError(err));
                        return;
                    }

                    if(!token || token.token != params.oauth_token) {
                        callback(new errors.OAuthUnauthorizedError("Invalid / expired Token"));
                        return;
                    }
  
                    if(token.token === undefined
                            || token.token_secret === undefined
                            || token.token_type === undefined) {
                        callback(new errors.OAuthProviderError(
                            "provider: tokenByConsumer must return an object "
                            +"with fields [token, secret, token_type]"));
                        return;
                    }
  
                    finish_validation(consumer, token);
                });
            }
    });
}

/**
  OAuth Methods
**/  
OAuthServices.prototype.authorize = function(request, callback) {
    var requestParameters = this.parseParameters(request);

    try {
      // Ensure correct parameters are available
      validateParameters(requestParameters, ['oauth_consumer_key', 'oauth_token',
              'oauth_signature_method', 'oauth_signature',
              'oauth_timestamp', 'oauth_nonce'])
    }
    catch(err) {
        callback(err, null);
        return
    }

    this.verifySignature(requestParameters, request, function(err, consumer, token) {
        if(err) {
            callback(err);
        }
        else if(token.token_type != 'access') {
            callback(new errors.OAuthBadRequestError(
                'Request token is invalid here'));
        }
        else {
            request.oauth_consumer = consumer;
            request.oauth_token = token;
            callback();
        }
    });
}

// Authenticate the user and validate the request token
OAuthServices.prototype.authorizeToken = function(user, oauthToken, callback) {
    this.provider.authorizeToken(user, oauthToken, function(err, result) {
      if(err) {
          callback(err, null);
          return;
      };
  
      if(!result.token || !result.verifier || !result.callback) {
          callback(new errors.OAuthProviderError(
              "authorizeToken must return a object with "+
              "fields [token, verifier, callback]"), null);
          return;
      }
  
      callback(null, result);      
    });
}

OAuthServices.prototype.requestToken = function(request, callback) { 
    var self = this,
        requestParameters = this.parseParameters(request);

    // Ensure correct parameters are available
    try {
        validateParameters(requestParameters, ['oauth_consumer_key',
            'oauth_signature_method', 'oauth_signature',
            'oauth_timestamp', 'oauth_nonce', 'oauth_callback']);
    }
    catch(err) {
        callback(err, null);
        return;
    }    

    // Fetch the secret and token for the user
    this.verifySignature(requestParameters, request, function(err, consumer) {
        if(err) {
            callback(err);
            return;
        }

        self.provider.generateRequestToken(
            requestParameters.oauth_consumer_key,
            requestParameters.oauth_callback,
            function(err, result) {
                if(err) {
                    callback(new errors.OAuthProviderError("internal error"));
                }
                else if(!result.token || !result.token_secret) {
                    callback(new errors.OAuthProviderError(
                        "provider: generateRequestToken must return a object "+
                        "with fields [token, token_secret]"), null);
                    return;
                }
                else {
                    result['oauth_callback_confirmed'] = true;
                    callback(null, result);                
                }
        });
    });
}

OAuthServices.prototype.accessToken = function(request, callback) { 
    var params = this.parseParameters(request);

    // Ensure correct parameters are available
    try {
        validateParameters(params, ['oauth_consumer_key', 'oauth_token',
              'oauth_signature_method', 'oauth_signature', 'oauth_timestamp',
              'oauth_nonce', 'oauth_verifier'])
    }
    catch(err) {
        callback(err);
        return
    }
    var self = this;

    this.verifySignature(params, request, function(err, consumer, token) {
        if(err)
            callback(err);

        else if(!token.verifier)
            callback(new errors.OAuthProviderError("getTokenByKey must return "
                +"verifier for request tokens"));

        else if(token.verifier != params.oauth_verifier)
            callback(new errors.OAuthUnauthorizedError("Invalid verifier for token"));

        else
            self.provider.generateAccessToken(params.oauth_token,
                function(err, result) {
                    if(!result.token || !result.token_secret) {
                        callback(new errors.OAuthProviderError(
                            "generateAccessToken must return a object with "
                            +"fields [token, token_secret]"));
                        return;
                    }

                    callback(null, result);
            });
    });
}

/**
  Internal Methods used for parsing etc
**/  
function validateParameters(parameters, requiredParameters) {
  if(!parameters) {
      throw(new errors.OAuthBadRequestError("Missing parameters!"));
  }

  requiredParameters.forEach(function(requiredParameter) {
    if(parameters[requiredParameter] == null)
        throw(new errors.OAuthBadRequestError(
            "Missing required parameter: "+requiredParameter));
  });
  return true;
}

// Escape as per OAuth 1.0a Section 5.1
function escape(s) {
    return querystring.escape(s)
            .replace(/\!/g, "%21")
            .replace(/\*/g, "%2A")
            .replace(/\'/g, "%27")
            .replace(/\(/g, "%28")
            .replace(/\)/g, "%29");
}

// Return the signature base string...
function getBaseString(request, parameters) {
    // Build a list of encoded key-values
    var values = [],
        query = urlparse(request.url, true).query;
    for(var p in parameters) {
        if(p != 'oauth_signature')
            values.push([p, parameters[p]]);
    }

    // Add querystring params...
    for(var p in query) {
        if(!parameters[p])
            values.push([p, query[p]]);
    }

    // Add POST parameters...
    if(request.method == 'POST'
        && request.headers['content-type'] == 'application/x-www-form-urlencoded') {
        for(var p in request.body) {
            if(!parameters[p])
                values.push([p, request.body[p]]);
        }
    }

    values = escape(values.map(function(p) {
        return escape(p[0])+'='+escape(p[1]);
        }).sort().join('&'));

    return [
        request.method.toUpperCase(),
        escape(request.protocol.toLowerCase()+'://'
            +request.headers['host'].toLowerCase()
            +urlparse(request.originalUrl || request.url).pathname),
        ].concat(values).join('&');
}

OAuthServices.prototype.calculateSignature = function(request,
    parameters, consumer_secret, token_secret)
{
    var baseString = getBaseString(request, parameters),
        key = escape(consumer_secret||'')+'&'+escape(token_secret||'');

    switch(parameters['oauth_signature_method']) {
    case 'HMAC-SHA1':
        return crypto.createHmac('sha1', key).update(baseString).digest('base64');
    case 'RSA-SHA1':
        throw('RSA-SHA1 signature method is unimplemented');
    case 'PLAINTEXT':
        return key;
    }
}

OAuthServices.prototype.parseParameters = function(req) {
  // Try Authorization header first...
  if(req.headers['authorization'] && req.headers['authorization'].indexOf('OAuth') != -1) {
    var parameters = {};

    // Trim the strings and split the values
    req.headers['authorization']
        .substring('OAuth '.length)
        .split(',')
        .forEach(function(str) {
      var p = str.trim(),
          i = p.indexOf('=')
          pname = p.substr(0,i)
          pval = p.substr(i+1);
      parameters[pname] = querystring.unescape(pval.replace(/^"|"$/g, ''));
    });

    return parameters;
  }
  else if(req.method == 'POST' &&
          req.headers['content-type'] == 'application/x-www-form-urlencoded' &&
          req.body['oauth_consumer_key'])
    // POST parameters next...
    return req.body;

  else
    // Finally look in the query string...
    return urlparse(req.url, true).query;
}
