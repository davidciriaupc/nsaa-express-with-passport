(async () => {
const config = require('./config.json');
const express = require('express')
const session = require('express-session');
const logger = require('morgan')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JWTStrategy = require('passport-jwt').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy
const GoogleOIDCStrategy = require('passport-google-oidc');
const GitHubStrategy = require('passport-github2').Strategy
const { Issuer, Strategy } = require('openid-client');
const OpenIDConnectStrategy = Strategy
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const scryptMcf = require('scrypt-mcf')
const { performance } = require('perf_hooks');
const axios = require('axios')

const RadiusClient = require('node-radius-client')
const {
  dictionaries: {
    rfc2865: {
      file,
      attributes,
    },
  },
} = require('node-radius-utils');
const radius_client = new RadiusClient({
  host: '10.0.2.8',
  dictionaries: [
    file,
  ],
});

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
passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (user, done) {
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
  function (accessToken, refreshToken, profile, done) {
    console.log("Google strategy middelware")
    // Aquí puedes guardar el perfil del usuario en la base de datos o en la sesión
    return done(null, profile);
  }
))

// 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
const oidcIssuer = await Issuer.discover(config['oauth']['google']['OIDC_PROVIDER'])

// 2. Setup an OIDC client/relying party.
const oidcClient = new oidcIssuer.Client({
  client_id: config.oauth.google.GOOGLE_CLIENT_ID,
  client_secret: config.oauth.google.GOOGLE_CLIENT_SECRET,
  redirect_uris: ['http://localhost:3000/callback-passport-oidc'],
  response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
})

// 3. Configure the strategy.
passport.use('passport-oidc-client', new OpenIDConnectStrategy({
  client: oidcClient,
  usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
}, (tokenSet, userInfo, done) => {
  console.log(tokenSet, userInfo)
  if (tokenSet === undefined || userInfo === undefined) {
    return done('no tokenSet or userInfo')
  }
  return done(null, userInfo)
}))

passport.use('google-oidc', new GoogleOIDCStrategy(
  {
    clientID: config.oauth.google.GOOGLE_CLIENT_ID,
    clientSecret: config.oauth.google.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/callback-oidc'
  },
  function verify(issuer, profile, cb) {
    console.log(profile);
    console.log("Google OIDC strategy");
    return cb(null, profile);
  })
);

passport.use('github', new GitHubStrategy({
  clientID: GITHUB_CLIENT_ID,
  clientSecret: GITHUB_CLIENT_SECRET,
  callbackURL: "http://127.0.0.1:3000/gitcallback",
  scope: ['user:email']
},
  function (accessToken, refreshToken, profile, done) {
    console.log("Github strategy middelware")
    return done(null, profile);
  }
));

passport.use('radius-strategy', new LocalStrategy(
  {
    usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
    passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
    session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
  },
  function (username, password, done) {
  // Send the RADIUS request to the server
  radius_client.accessRequest({
    secret: 'testing123',
    attributes: [
      [attributes.USER_NAME, username + "@upc.edu"], //using realm "upc.edu".
      [attributes.USER_PASSWORD, password]
    ],
  }).then((result) => {
    console.log('result', result);
    result['username'] = username + "@upc.edu";
    return done(null, result);
  }).catch((error) => {
    console.log('error', error);
    return done(null, false);
  });

}));

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

app.use(logger('dev'))

app.get('/',
  passport.authenticate(['jwt-token'], { failureRedirect: '/login', session: false }),
  (req, res) => {
    const header = "<h1> Hello " + req.user.sub + " </h1>\n"
    const message = fortune.fortune()
    const logout_button = '<form action="/logout" method="get"><input type="submit" value="Logout"></input></form>'
    res.send(header + message + logout_button);
  })

app.get('/login',
  (req, res) => {
    if (req.query.authFailed === 'true') {
      res.sendFile('login_error.html', { root: __dirname })
    } else {
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

app.post('/login-radius',
  passport.authenticate('radius-strategy', { failureRedirect: '/login?authFailed=true', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
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
  } else {
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
    } else {
      res.redirect('/register?regFailed=true')
    }

  } else {
    res.redirect('/register')
  }
})

app.get('/google',
  passport.authenticate('google', { scope: ['email', 'https://www.googleapis.com/auth/trace.readonly'] }));

app.get('/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    console.log("Google login callback")
    const emails = req.user.emails
    if (emails && emails.length == 1) {
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
    } else {
      res.redirect('/login');
    }
  });

app.get('/passport-oidc',
passport.authenticate('passport-oidc-client', {scope: 'openid email'}));

app.get('/callback-passport-oidc',
  passport.authenticate('passport-oidc-client', { failureRedirect: '/login' }),
  function (req, res) {
    console.log("Google login callback")
    const email = req.user.email
    if (email) {
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
    } else {
      res.redirect('/login');
    }
  });

app.get('/google-oidc',
  passport.authenticate('google-oidc', {scope: ['email', 'openid']}));

app.get('/callback-oidc',
  passport.authenticate('google-oidc', { failureRedirect: '/login' }),
  function (req, res) {
    console.log("Google login callback")
    const emails = req.user.emails
    if (emails && emails.length == 1) {
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
    } else {
      res.redirect('/login');
    }
  });

app.get('/github',
  passport.authenticate('github', { scope: ['user:email'] }));

app.get('/gitcallback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function (req, res) {
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

// Github oauth2 manual.
app.get('/gitmancallback', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
  /**
   * 1. Retrieve the authorization code from the query parameters
   */
  const code = req.query.code // Here we have the received code
  if (code === undefined) {
    const err = new Error('no code provided')
    err.status = 400 // Bad Request
    throw err
  }

  /**
   * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
   */
  const tokenResponse = await axios.post(config.oauth.github.OAUTH2_TOKEN_URL, {
    client_id: config.oauth.github.GITHUB_CLIENT_ID,
    client_secret: config.oauth.github.GITHUB_CLIENT_SECRET,
    code
  })

  console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.

  // Let us parse them ang get the access token and the scope
  const params = new URLSearchParams(tokenResponse.data)
  const accessToken = params.get('access_token')
  const scope = params.get('scope')

  // if the scope does not include what we wanted, authorization fails
  if (scope !== 'user:email') {
    const err = new Error('user did not consent to release email')
    err.status = 401 // Unauthorized
    throw err
  }

  /**
   * 3. Use the access token to retrieve the user email from the USER_API endpoint
   */
  const userDataResponse = await axios.get(config.oauth.github.USER_API, {
    headers: {
      Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
    }
  })
  console.log(userDataResponse.data)
  let primary_email = "";
  userDataResponse.data.forEach((email) => {
    if (email.primary) {
      primary_email = email.email;
    }
  })

  /**
   * 4. Create our JWT using the github email as subject, and set the cookie.
   */
  const jwtClaims = {
    sub: primary_email,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
    role: 'user' // just to show a private JWT field
  }
  const token = jwt.sign(jwtClaims, jwtSecret)
  res.cookie('token', token, { httpOnly: true, secure: true })

  // Successful authentication, redirect home.
  res.redirect('/');
})

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
})();