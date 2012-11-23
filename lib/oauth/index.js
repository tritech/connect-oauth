var querystring = require('querystring'),
    url = require('url'),
    join = require('path').join,
    connect = require('connect'),
    services = require('./oauth_services'),
    errors = require('./oauth_error');

 /**
  * Initialize Oauth options.
  *
  * Options:
  *
  *   - realm
  *   - request_token_url        'web path for the request token url endpoint, default: <realm>/request_token'
  *   - authorize_url            'web path for the authorize form, default: <realm>/authorize' (get/post)
  *   - access_token_url         'web path for the access token url endpoint, default: <realm>/access_token'
  *   - authorize_form_provider  'function to render a authentication form'
  *   - authorize_provider       'function to validate user credentials'
  *   - data_provider            'db instance providing needed authentication mechanisms'
  *
  * @param  {hash} options
  * @api private
  **/
function OAuth(options) {
    options = options || {};
    // Ensure we have default values and legal options
    if(!options.realm)
        throw Error("OAuth realm has not been defined");

    var authorize_form_provider = options.authorize_form_provider,
        authorize_provider = options.authorize_provider;
  
    // Both authorize handler and oauth provider must be provided
    if(!authorize_form_provider || !authorize_provider)
        throw Error("authorize_form_provider and authorize_provider are required");

    if(!options.data_provider)
        throw Error("data_provider required");

    // Set up the OAuth provider and data source
    this.authorize_provider = authorize_provider;
    this.authorize_form_provider = authorize_form_provider;
    this.oauth_service = new services.OAuthServices(options.data_provider);
    this.realm = options.realm;
}


/**
OAuth Methods Handle the Request token request
**/
OAuth.prototype.requestToken = function(request, response, next) { 
    this.oauth_service.requestToken(request, function(err, result) {    
      if(err) {
          next(err);
      }
      else {
        response.writeHead(200, {'Content-Type':'application/x-www-form-urlencoded'});
        response.end(["oauth_token=" + result["token"],
            "oauth_token_secret=" + result["token_secret"],
            "oauth_callback_confirmed=" + result["oauth_callback_confirmed"]
            ].join("&"));            
      }
    });
};


/**
OAuth Methods Handle the Authorization form postback
**/
OAuth.prototype.authorizeToken = function(user, oauth_token, res, next) {
    this.oauth_service.authorizeToken(user, oauth_token, function(err, result) {
        if(err) {
            next(err);
        }
        else if(result.callback && result.callback != "oob") {
            var callback = querystring.unescape(result.callback),
                redirect_url = url.parse(callback, true);

            redirect_url.query = redirect_url.query || {};
            redirect_url.query.oauth_token = result.token;
            redirect_url.query.oauth_verifier = result.verifier;

            res.writeHead(307, {'Location': url.format(redirect_url)});
            res.end();
        }
        else {
            // Callback is oob, just return a 200 for now
            // TODO: Allow the application to display a user interface here
            res.writeHead(200, {'Content-Type':'application/x-www-form-urlencoded'});
            res.end([
                'oauth_token='+result.token,
                'oauth_verifier='+result.verifier].join('&'));
        }
    });
}

/**
OAuth Methods Handle the Retrieve Access token
**/
OAuth.prototype.accessToken = function(req, resp, next) {
    this.oauth_service.accessToken(req, function(err, result) {
        if(err) {
            next(err);
        }
        else {
            resp.writeHead(200,
                {'Content-Type': 'application/x-www-form-urlencoded'});
            resp.end(querystring.stringify({
                    oauth_token: result.token,
                    oauth_token_secret: result.token_secret
                }));
        }
    });
}

OAuth.prototype.verifyRequest = function(req, resp, next) {
    this.oauth_service.authorize(req, next);
}


exports.createProvider = function(options) {
    var provider = new OAuth(options),

        realm = url.parse(options.realm),
        protocol = realm.protocol.substr(0, realm.protocol.length-1),

        request_token_url = options.request_token_url || '/request_token',
        authorize_url     = options.authorize_url || '/authorize',
        access_token_url  = options.access_token_url || '/access_token';


    var app = connect()
        .use(function(req, res, next) {
            // Add request.protocol...
            if(!req.protocol)
                req.protocol = protocol;
            next();
        })
        .use(request_token_url, function(req, resp, next) {
            provider.requestToken(req, resp, next);
        })
        .use(authorize_url, function(req, resp, next) {
            if(req.method != 'POST')
                return provider.authorize_form_provider(req, resp, next);

            provider.authorize_provider(req, resp, function(err, user) {
                if(err) return next(err);
                provider.authorizeToken(user, req.body.oauth_token, resp, next);
            });
        })
        .use(access_token_url, function(req, resp, next) {
            provider.accessToken(req, resp, next);
        })
        .use(function(req, res, next) {
            provider.verifyRequest(req, res, next);
        });

    // Error handler...
    app.use(function(err, req, res, next) {
        if(err.statusCode !== 401) return next(err);

        res.writeHead(401, {
            'Content-Type': 'text/plain',
            'WWW-Authenticate': 'OAuth realm="'+ provider.realm +'"'
        });
        res.end(err.message || err);
    });

    return app;
}

// Generate a new random token (or token secret)
exports.generateToken = function(length, chars) {
    chars = chars || "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
    var result = '';
    for(var i = 0; i < length; ++i)
        result += chars[Math.floor(Math.random() * chars.length)]
    return result;
}


exports.errors = errors;
