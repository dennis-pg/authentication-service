const app = require('@greenpress/api-kit').app()
const cookieParser = require('cookie-parser')


const verifyUser = require('../middleware/verify-user')
const { onlyAuthenticated } = require('../middleware/auth-check')

<<<<<<< HEAD
app.use(cookieParser);
=======
app.use(require('cookie-parser')())
>>>>>>> ab0c3e633035435a66e80fe12d73a6c65a096b09

app
	.post('/api/signin', require('../controllers/signin'))
	.post('/api/signup', require('../controllers/signup'))
	.post('/api/token/refresh', require('./refresh-token'))
	.get('/api/me', verifyUser, onlyAuthenticated, require('./me'))

app.use(require('./users'))
