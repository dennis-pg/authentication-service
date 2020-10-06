const validator = require('validator');

function validateBasicSignInSignUpForm(payload) {
	const errors = {};
	console.log(payload, typeof payload.email)
	if (!payload || typeof payload.email !== 'string' || !validator.isEmail(payload.email.trim())) {
		errors.email = {
			code: 'INVALID_EMAIL'
		};
	}

	return errors;
}

module.exports = {
	validateBasicSignInSignUpForm
};