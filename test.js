var createClient = require('./')
var test = require('tape')
var nets = require('nets')

var creds = {
  id: process.env['AUTH0TESTID'],
  secret: process.env['AUTH0TESTSECRET'],
  domain: process.env['AUTH0TESTDOMAIN'],
  connection: process.env['AUTH0TESTCONNECTION'],
  token: process.env['AUTH0TESTTOKEN']
}

if (!creds.id || !creds.secret || !creds.domain || !creds.connection || !creds.token) throw new Error('must set env vars')

test('delete existing test user if exists', function (t) {
  var headers = {
    'Authorization': 'Bearer ' + creds.token
  }
  var query = '?connection=' + creds.connection
  nets({url: 'https://' + creds.domain + '/api/v2/users' + query, headers: headers, method: 'GET', json: true}, function (err, resp, body) {
    t.ifErr(err)    
    if (!body || !body.length) return t.end()
    var first = body[0]
    nets({url: 'https://' + creds.domain + '/api/v2/users/' + first.user_id + query, headers: headers, method: 'DELETE', json: true}, function (err, resp, body) {
      t.ifErr(err, 'check response error')
      t.equals(resp.statusCode, 204, 'deleted user')
      t.end()
    })
  })
})

test('signup', function (t) {
  var json = {
    "client_id": creds.id,
    "connection": creds.connection,
    "email": "foo@example.com",
    "username": "foo",
    "password": "foobar"
  }
  nets({url: 'https://' + creds.domain + '/dbconnections/signup', method: 'POST', json: json}, function (err, resp, body) {
    t.ifErr(err)
    t.equals(resp.statusCode, 200, '200 OK created user')
    t.ok(body._id, 'got user _id')
    t.end()
  })
})

test('login', function (t) {
  var json = {
    "client_id": creds.id,
    "connection": creds.connection,
    "grant_type": "password",
    "username": "foo",
    "password": "foobar",
    "scope": "openid"
  }
  nets({url: 'https://' + creds.domain + '/oauth/ro', method: 'POST', json: json}, function (err, resp, body) {
    t.ifErr(err)
    t.equals(resp.statusCode, 200, 'logged in OK')
    t.ok(body.id_token, 'got id_token')
    t.ok(body.access_token, 'got access_token')
    t.equals(body.token_type, 'bearer', 'is bearer type')
    t.end()
  })
})
