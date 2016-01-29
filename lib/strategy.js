var passport = require('passport-strategy'),
    util = require('util'),
    AWS = require('aws-sdk');

/**
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 */
function Strategy(options, verify) {
    this.name = 'cognito';
    this._verify = verify;

    this._developerProvider = options.developerProvider;
    this._identityPoolId = options.identityPoolId;
    this._region = options.region;
    this._callbackURL = options.callbackURL;
    this._awsSdkProfile = options.profile || null;

    this._passReqToCallback = options.passReqToCallback;

    if (this._awsSdkProfile) AWS.config.credentials = new AWS.SharedIniFileCredentials({ profile: this._awsSdkProfile });
    AWS.config.region = this._region;
    this._cognitoIdentity = new AWS.CognitoIdentity();
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function (req, options) {
    var self = this;

    var Logins = {};
    console.log(req.user);
    Logins[self._developerProvider] = req.user.profiles[0].credentials.accessToken;
    var params = {
        IdentityPoolId: self._identityPoolId,
        Logins: Logins
    }

    for (var p in req.user.profiles) {
        if (p.name === 'cognito') {
            if (p.identityId) params['IdentityId'] = p.identityId;
            else throw new TypeError('Corrupted Data');
        }
    }

    function verified(err, user, info) {
        console.log('Verifying...');
        if (err) {
            console.log('Error');
            return self.error(err);
        }
        if (!user) {
            console.log('No user');
            return self.fial(info);
        }
        console.log('Verified succesfully', user, info);
        self.success(user, info);
    }

    this._cognitoIdentity.getOpenIdTokenForDeveloperIdentity(params, function (err, data) {
        if (err) console.log(err);
        else {
            var profile = {};
            profile.id = data.IdentityId;
            console.log(data.IdentityId);
            if (self._passReqToCallback) self._verify(req, self._developerProvider, profile, data.Token, verified)
            else self._verify(self._developerProvider, profile, data.Token, verified);
        }

        self.redirect(self._callbackURL);
    });
};

module.exports = Strategy;