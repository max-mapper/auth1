var decode = require('jwt-decode')
var qs = require('querystring')

/**
 * Assert util.
 */

function assert(e, msg) {
  if (!e) throw new Error(msg)
}

/**
 * Export Auth0.
 */

module.exports = Auth0;

/**
 * Auth0 client:
 *
 * - clientID: client ID (required)
 * - domain: client domain (required)
 */

function Auth0(config) {
  assert(config, 'config required')
  assert(config.clientID, '.clientID required')
  assert(config.domain, '.domain required')
  this.clientID = config.clientID
  this.domain = config.domain
}

/**
 * Check if `token` is expired.
 */

Auth0.prototype.isExpired = function(token) {
  var expires = new Date(this.decodeJwt(token).exp * 1000)
  return new Date >= expires
}

/**
 * Get profile data by `id_token`.
 */

Auth0.prototype.getProfile = function(id_token, cb) {
  assert('function' == typeof cb, 'callback required')
  assert('string' == typeof id_token, 'id_token must be a string')
  this._getUserInfo(this.decodeJwt(id_token), id_token, cb)
}

/**
 * Decode Json Web Token.
 */

Auth0.prototype.decodeJwt = function(jwt) {
  assert(jwt, 'jwt required')
  return decode(jwt)
}

/**
 * Get user information from API.
 */

Auth0.prototype._getUserInfo = function(profile, id_token, cb) {
  if (profile && profile.user_id) {
    return cb(null, profile)
  }

  // TODO: https://auth0.com/docs/libraries/lock/sending-authentication-parameters#scope-string-
  assert(false, 'unimplemented')
}

/**
 * Given the hash (or a query) of an URL returns a dictionary with only relevant
 * authentication information. If succeeds it will return the following fields:
 * `profile`, `id_token`, `access_token` and `state`. In case of error, it will
 * return `error` and `error_description`.
 */

Auth0.prototype.parseHash = function(hash) {
  hash = hash || window.location.hash

  // error
  if (hash.match(/error/)) {
    hash = hash.substr(1).replace(/^\//, '')
    var res = qs.parse(hash)
    return {
      error: res.error,
      error_description: res.error_description
    }
  }

  // invalid hash URL
  if(!hash.match(/access_token/)) {
    return
  }

  hash = hash.substr(1).replace(/^\//, '')
  var res = qs.parse(hash)
  var id_token = res.id_token
  var refresh_token = res.refresh_token
  var prof = this.decodeJwt(id_token)

  function invalidJwt(error) {
    return {
      error: 'invalid_token',
      error_description: error
    }
  }

  // aud should be the clientID
  var audiences = Array.isArray(prof.aud) ? prof.aud : [prof.aud];
  if (audiences.indexOf(this.clientID) == -1) {
    return invalidJwt(
      'The clientID configured (' + this.clientID + ') does not match with the clientID set in the token (' + audiences.join(', ') + ').');
  }

  // iss should be the Auth0 domain (i.e.: https://contoso.auth0.com/)
  if (prof.iss && prof.iss !== 'https://' + this.domain + '/') {
    return invalidJwt(
      'The domain configured (https://' + this.domain + '/) does not match with the domain set in the token (' + prof.iss + ').');
  }

  return {
    accessToken: res.access_token,
    idToken: id_token,
    idTokenPayload: prof,
    refreshToken: refresh_token,
    state: res.state
  }
}
