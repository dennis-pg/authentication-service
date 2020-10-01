const jwt = require('jsonwebtoken')
const { jwtSecret, refreshTokenSecret } = require('../../config')

function verifyToken (token, tenant) {
  if (!token.trim()) {
    return Promise.reject()
  }
  return verify(token, tenant, jwtSecret);
}

function verifyRefreshToken (refreshToken, tenant) {
  return verify(refreshToken, tenant, refreshTokenSecret);
}

function verify (token, tenant, secret) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secret, (err, decoded) => {
      if (err || !decoded || decoded.tenant !== tenant) {
        // the 401 code is for unauthorized status
        return reject(err || { message: 'token is empty' })
      }
      return resolve(decoded)
    })
  })
}

function createUniqueId (creationTime = Date.now()) {
	console.log('create uniq id')
	console.log(creationTime.toString() + Buffer.from(Math.random().toString()).toString('base64'))
	return creationTime.toString() + Buffer.from(Math.random().toString()).toString('base64')
}


module.exports = {
  verifyToken,
  verifyRefreshToken,
  createUniqueId
}
