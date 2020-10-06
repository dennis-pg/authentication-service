const User = require('../models/user')

async function getUser (query) {
	try {
		const user = await User.findOne(query)
		if (user) {
			return user
		}
	} catch (err) {
		throw { code: 'FORM_SUBMISSION_FAILED', info: err }
	}

	throw { code: 'INCORRECT_CREDENTIALS' }
}

function updateUser (user, { email = null, password = null, name = null, roles = null }) {
	if (email) {
		user.email = email
	}

	if (password) {
		user.password = password
	}

	if (name) {
		user.name = name
	}

	if (roles) {
		user.roles = roles
	}

	return user.save()
		.catch(err => Promise.reject({ code: 'UPDATE USER FAILED', info: err }))
}

function deleteUser (userId, tenant) {
	User.deleteOne({ _id: userId, tenant })
		.then((() => Promise.resolve({ code: 'USER DELETED SUCCESSFULLY', info: user._id })))
		.catch((error) => Promise.reject({ code: 'USER DELETE FAILED', info: error }))
}

function comparePassword (user, password) {
	return new Promise((resolve, reject) => {
		return user.comparePassword(password.trim(), (passwordErr, isMatch) => {
			if (passwordErr) {
				return reject({ code: 'FORM_SUBMISSION_FAILED', info: passwordErr })
			}
			if (!isMatch) {
				return reject({ code: 'INCORRECT_CREDENTIAL' })
			}
			resolve(user)
		})
	})
}

function setToken (user, authType) {
	if (authType === 'oauth') {
		return setOAuthAuthentication(user, authType)
	}
	if (authType === 'cookie') {
		return setCookieAuthentication(user)
	}
	throw { code: 'INVALID AUTH TYPE' }
}

function updateToken (user, authType, currentToken, newToken) {
	return user.updateToken(authType, currentToken, newToken)
		.catch(err => Promise.reject({ code: 'UPDATE TOKEN FAILED', info: err }))
}

function deleteToken (user, authType, token) {
	return user.deleteToken(authType, token)
		.catch(err => Promise.reject({ code: 'DELETE TOKEN FAILED', info: err }))
}

function setOAuthAuthentication (user) {
	const token = user.getToken('oauth')
	const refreshToken = user.getRefreshToken(token)

	return user.save().then(() => {
		return {
			token,
			refreshToken,
			user
		}
	})
}

function setCookieAuthentication (user) {
	const cookieToken = user.getToken('cookie')

	return user.save().then(() => {
		return { user, cookieToken }
	})
}

async function checkIfTokenExists (tokenId) {
	return User.findOne({'tokens.tokenIdentifier': tokenId});
}

module.exports = {
	getUser,
	updateUser,
	deleteUser,
	comparePassword,
	setToken,
	updateToken,
	deleteToken,
	checkIfTokenExists
}
