var EventEmitter = require('events').EventEmitter;
var _ = require('underscore');
var http = require('request');
var RSVP = require('rsvp');
var jwt = require('jwt-simple');
var urls = require('url');

function HipChat(addon, app){
    var self = this;

    // override the following...
    addon.middleware = self.middleware;
    addon.authenticate = self.authenticate;
    addon._configure = self._configure;
    addon._getAccessToken = self._getAccessToken;

    // Disable auto-registration... not necessary with HipChat
    addon.register = function(){
        self.logger.info('Auto registration not available with HipChat add-ons')
    };

    addon._verifyKeys = function(){};

    // mixin the addon
    _.extend(self, addon);
}

var proto = HipChat.prototype = Object.create(EventEmitter.prototype);

proto._getAccessToken = function(clientInfo, scopes) {
    var self = this;
    function generateAccessToken(scopes){
        return new RSVP.Promise(function(resolve, reject){
            var tokenUrl = clientInfo.capabilitiesDoc.capabilities.oauth2Provider.tokenUrl;
            http.post(tokenUrl, {
                form: {
                    'grant_type': 'client_credentials',
                    'scope': scopes.join(' ')
                },
                auth: {
                    user: clientInfo.clientKey,
                    pass: clientInfo.oauthSecret
                }
            }, function(err, res, body){
                if(!err) {
                    try {
                        var token = JSON.parse(body);
                        token.created = new Date().getTime() / 1000;
                        resolve(token);
                    } catch(e) {
                        reject(e);
                    }
                } else {
                    reject(err);
                }
            });
        });
    }

    return new RSVP.Promise(function(resolve, reject){
        scopes = scopes || self.descriptor.capabilities.hipchatApiConsumer.scopes;
        var scopeKey = scopes.join("|");

        function generate() {
            generateAccessToken(scopes).then(
                function(token) {
                    self.settings.set(scopeKey, token, clientInfo.clientKey);
                    resolve(token);
                },
                function(err) {
                    reject(err);
                }
            );
        }

        self.settings.get(scopeKey, clientInfo.clientKey).then(function(token){
            if (token) {
                if (token.expires_in + token.created < (new Date().getTime() / 1000)) {
                    resolve(token);
                } else {
                    generate();
                }
            } else {
                generate();
            }
        }, function(err) {
            reject(err);
        });
    });
};

proto._configure = function(){
    var self = this;
    var baseUrl = urls.parse(self.config.localBaseUrl());
    var basePath = baseUrl.path && baseUrl.path.length > 1 ? baseUrl.path : '';

    self.app.get(basePath + '/atlassian-connect.json', function (req, res) {
        res.json(self.descriptor);
    });

    // HC Connect install verification flow
    function verifyInstallation(url){
        return new RSVP.Promise(function(resolve, reject){
            http.get(url, function(err, res, body){
                var data = JSON.parse(body);
                if(!err){
                    if(data.links.self === url){
                        resolve(data);
                    } else {
                        reject("The capabilities URL " + url + " doesn't match the resource's self link " + data.links.self);
                    }
                } else {
                    reject(err);
                }
            });
        });
    };

    // register routes for installable handler
    if (typeof self.descriptor.capabilities.installable != 'undefined') {
        var callbackUrl = '/'+self.descriptor.capabilities.installable.callbackUrl.split('/').slice(3).join('/');

        // Install handler
        self.app.post(

            // mount path
            callbackUrl,

            // TODO auth middleware

            // request handler
            function (req, res) {
                try {
                    verifyInstallation(req.body.capabilitiesUrl)
                        .then(function(hcCapabilities){
                            var clientInfo = {
                                clientKey: req.body.oauthId,
                                oauthSecret: req.body.oauthSecret,
                                capabilitiesUrl: req.body.capabilitiesUrl,
                                capabilitiesDoc: hcCapabilities
                            };
                            self._getAccessToken(clientInfo)
                                .then(function(tokenObj){
                                    clientInfo.groupId = tokenObj.group_id;
                                    clientInfo.groupName = tokenObj.group_name;
                                    self.emit('installed', clientInfo.clientKey, clientInfo, req.body);
                                    self.emit('plugin_enabled', clientInfo.clientKey, clientInfo);
                                    self.settings.set('clientInfo', clientInfo, clientInfo.clientKey).then(function (data) {
                                        self.logger.info("Saved tenant details for " + settings.clientKey + " to database\n" + util.inspect(data));
                                        self.emit('host_settings_saved', settings.clientKey, data);
                                        res.send(204);
                                    }, function (err) {
                                        res.send(500, 'Could not lookup stored client data for ' + settings.clientKey + ': ' + err);
                                    });
                                    res.send(204);
                                })
                                .then(null, function(err){
                                    res.send(500, err);
                                });
                        })
                        .then(null, function(err){
                            res.send(500, err);
                        }
                    );
                } catch (e) {
                    res.send(500, e);
                }
            }
        );
    }

    // uninstall handler
    self.app.delete(
        callbackUrl + '/:oauthId',
        // verify request,
        function(req, res){
            try {
                self.emit('uninstalled', req.params.oauthId);
                res.send(204);
            } catch (e) {
                res.send(500, e);
            }
        }
    );
}

// Middleware to verify jwt token
proto.authenticate = function(){
    var self = this;
    return function(req, res, next){
        function send(code, msg) {
            self.logger.error('JWT verification error:', code, msg);
            res.send(code, msg);
        }

        if (req.query.signed_request) {
            try {
                // First get the oauthId from the JWT context by decoding it without verifying
                var clientId = jwt.decode(req.query.signed_request, null, true).iss;

                // Then, let's look up the client's oauthSecret so we can verify the request
                self.loadClientInfo(clientId).then(function(clientInfo){
                    // verify the signed request
                    if (clientInfo === null) {
                        return send(400, "Request can't be verified without an OAuth secret");
                    }
                    var request = jwt.decode(req.query.signed_request, clientInfo.oauthSecret);
                    req.context = request.context;
                    req.clientInfo = clientInfo;
                    console.log(req.context);
                    next();
                }, function(err) {
                    return send(400, err.message);
                });
            } catch(e){
                return send(400, e.message);
            }
        } else if (req.body.oauth_client_id) {
            self.settings.get('clientInfo', req.body.oauth_client_id).then(function(d){
                try {
                    req.clientInfo = d;
                    req.context = req.body;
                    next();
                } catch(e){
                    return send(400, e.message);
                }
            });
        } else {
            return send(400, "Request not signed and therefore can't be verified");
        }
    }
}

module.exports = function(addon, app){
    return new HipChat(addon, app);
}