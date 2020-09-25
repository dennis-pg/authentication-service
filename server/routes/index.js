const app = require('@greenpress/api-kit').app()
const cookieParser = require('cookie-parser')


const verifyUser = require('../middleware/verify-user')
const { onlyAuthenticated } = require('../middleware/auth-check')

app.use(cookieParser);

app
	.post('/api/signin', require('../controllers/signin'))
	.post('/api/signup', require('../controllers/signup'))
	.post('/api/token/refresh', require('./refresh-token'))
	.get('/api/me', verifyUser, onlyAuthenticated, require('./me'))

app.use(require('./users'))
