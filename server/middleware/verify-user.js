const { verifyToken, getUniqueId, setCookie } = require('../services/tokens')
const { checkIfTokenExists, updateToken } = require('../services/users')
const { privilegedRoles } = require('../../config')


function oAuthVerify (req, res, next) {
	// get the last part from a authorization header string like "bearer token-value"
	const token = req.headers.authorization.split(' ')[1]
	const tenant = req.headers.tenant = req.headers.tenant || '0'

	return verifyToken(token, tenant)
		.then(payload => {
			// pass user details onto next route
			req.userPayload = payload
			req.userPayload.isPrivileged = payload.roles.some(role => privilegedRoles.includes(role))
			return next()
		})
		.catch(() => {
			return next()
		})
}

function cookieVerify (req, res, next) {
	// get the last part from a authorization header string like "bearer token-value"
	const token = req.signedCookies.token || req.cookies.token
	const tenant = req.headers.tenant = req.headers.tenant || '0'

	return verifyToken(token, tenant)
		.then(payload => {
			const created = Number(payload.tokenIdentifier?.split(':')[0])
			if (Date.now() - created < 1000 * 60 * 10) { // less than 10 minutes - approved
				req.userPayload = payload
				req.userPayload.isPrivileged = payload.roles.some(role => privilegedRoles.includes(role))
				return next()
			} else {
				const user = checkIfTokenExists(payload.tokenIdentifier);
				if (user) {
					const newCookieIdentifier = getUniqueId();
					updateToken(user, 'cookie', payload.tokenIdentifier, newCookieIdentifier)
					.then(() =>{
						req.userPayload = payload;
						req.userPayload.isPrivileged = payload.roles.some(role => privilegedRoles.includes(role));
						req.userPayload.newCookieIdentifier = newCookieIdentifier;
						res = setCookie(res, newCookieIdentifier);
						return next();
					})
					.catch((err) => {
						return new Error(`FAILED TO UPDATE NEW TOKEN IN USER`);
					})

				} else {
					return new Error(`TOKEN DOESN'T EXIST`);
				}
			}
		})
		.catch(() => {
			return next()
		})
}

/**
 *  The Auth Checker middleware function.
 */
module.exports = (req, res, next) => {
	if (req.cookies.token || req.signedCookies.token) {
		return cookieVerify(req, res, next)
	} else if (req.headers.authorization) {
		return oAuthVerify(req, res, next)
	}
	return next()
}
