const config = require('./config.json');
const express = require('express')
const session = require('express-session');
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JWTStrategy = require('passport-jwt').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy
const GitHubStrategy = require('passport-github2').Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const scryptMcf = require('scrypt-mcf')
const { performance } = require('perf_hooks');

const FileDatabase = require('./database')
const file_database = new FileDatabase('database.json')

const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 
const app = express()
const port = 3000

const GOOGLE_CLIENT_ID = config['oauth']['google']['GOOGLE_CLIENT_ID']
const GOOGLE_CLIENT_SECRET = config['oauth']['google']['GOOGLE_CLIENT_SECRET']

const GITHUB_CLIENT_ID = config['oauth']['github']['GITHUB_CLIENT_ID']
const GITHUB_CLIENT_SECRET = config['oauth']['github']['GITHUB_CLIENT_SECRET']

app.use(cookieParser());

app.use(session({
  secret: jwtSecret.toString('utf8'),
  resave: false,
  saveUninitialized: true,
}));

// Configura la serialización y deserialización del usuario
passport.serializeUser(function(user, done) {
  done(null, user);
});
passport.deserializeUser(function(user, done) {
  done(null, user);
});

/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user.  The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('username-password', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  async function (username, password, done) {
    console.log("Local strategy middelware")
    const user = file_database.getUser(username)
    let db_password;
    if (user) { db_password = user['password'] }
    const start = performance.now()
    if (user && db_password && await scryptMcf.verify(password, db_password)) {
      const end = performance.now()
      console.log(`Time to compute hash: ${Math.round(end - start).toFixed(0)} milliseconds`)
      const user = {
        username: username
      }
      return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
    }
    return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
  }
))

passport.use('jwt-token', new JWTStrategy(
  {
    jwtFromRequest: (req) => req.cookies.token,
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {
    console.log("JWT strategy middelware")
    return done(null, jwtPayload) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
  }
))

passport.use('google', new GoogleStrategy(
  {
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/callback'
  },
  function(accessToken, refreshToken, profile, done) {
    console.log("Google strategy middelware")
    // Aquí puedes guardar el perfil del usuario en la base de datos o en la sesión
    return done(null, profile);
  }
))

passport.use('github', new GitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "http://127.0.0.1:3000/gitcallback",
  scope: ['user:email']
},
function(accessToken, refreshToken, profile, done) {
    console.log("Github strategy middelware")
    return done(null, profile);
}
));

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.use(logger('dev'))

app.get('/',
  passport.authenticate(['jwt-token'], { failureRedirect: '/login', session: false }),
  (req, res) => {
    const message = fortune.fortune()
    const logout_button = '<form action="/logout" method="get"><input type="submit" value="Logout"></input></form>'
    res.send(message + logout_button);
  })

app.get('/login',
  (req, res) => {
    if (req.query.authFailed === 'true') {
      res.sendFile('login_error.html', { root: __dirname }) 
    }else{
      res.sendFile('login.html', { root: __dirname })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
    }
  }
)

app.post('/login',
  passport.authenticate('username-password', { failureRedirect: '/login?authFailed=true', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {

    // This is what ends up in our JWT
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7dias×24horas×60minutos×60segundos=604800s) from now
      role: 'user', // just to show a private JWT field,
      exam: 'Ciria'
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    const token = jwt.sign(jwtClaims, jwtSecret)

    // From now, just send the JWT directly to the browser. Later, you should send the token inside a cookie.
    res.cookie('token', token, { httpOnly: true, secure: true })
    res.redirect('/')

    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/register', (req, res) => {
  if (req.query.regFailed === 'true') {
    res.sendFile('register_error.html', { root: __dirname })
  }else{
    res.sendFile('register.html', { root: __dirname })
  }
})

app.post('/register', async (req, res) => {
  const form_params = req.body
  const username = form_params['username']
  const password = form_params['password']

  if (username && password) {
    const reg_res = await file_database.registerUser(username, password)
    // If the user has been registered succesfully.
    if (reg_res) {
      res.redirect('/login')
    }else{
      res.redirect('/register?regFailed=true')
    }
    
  }else{
    res.redirect('/register')
  }
})

app.get('/google',
  passport.authenticate('google', { scope: ['email'] }));

app.get('/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    console.log("Google login callback")
    const emails = req.user.emails
    if(emails && emails.length == 1){
      const email = req.user.emails[0]['value']
      // This is what ends up in our JWT
      const jwtClaims = {
        sub: email,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
      }
      const token = jwt.sign(jwtClaims, jwtSecret)
      res.cookie('token', token, { httpOnly: true, secure: true })

      // Successful authentication, redirect home.
      res.redirect('/');
    }else{
      res.redirect('/login');
    }
  });

  app.get('/github',
  passport.authenticate('github', { scope: ['user:email'] }));

app.get('/gitcallback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    console.log("Github login callback")
    console.log(req.user)
      const jwtClaims = {
        sub: req.user.username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
      }
      const token = jwt.sign(jwtClaims, jwtSecret)
      res.cookie('token', token, { httpOnly: true, secure: true })

      // Successful authentication, redirect home.
      res.redirect('/');
   
  });

app.get('/logout', (req, res) => {
  res.clearCookie('token')
  res.redirect('/login')
});

app.use(function (err, req, res, next) {
  console.error(err.stack)
  res.status(500).send('Something broke!')
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})
