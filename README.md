# passport-cookie-session

[![npm version](https://img.shields.io/npm/v/passport-cookie-session.svg)](https://www.npmjs.com/package/passport-cookie-session)

A simple Express middleware to manage encrypted cookie sessions, designed to work seamlessly with Passport.js authentication.

This package stores session data directly in an encrypted cookie, eliminating the need for a server-side session store.

## Features

- Encrypts session data in cookies using AES-256-GCM.
- Supports multiple keys for key rotation.
- Fully compatible with Passport.js.
- Configurable cookie options (`httpOnly`, `secure`, `sameSite`, etc).
- Minimal and easy to integrate with Express apps.

## Installation

```bash
npm install passport-cookie-session
```

## Usage

```js
const express = require('express');
const passport = require('passport');
const passportCookieSession = require('passport-cookie-session');
const app = express();

app.use(passportCookieSession({
  name: 'auth',
  keys: ['super-secret-key', 'old-key'], // First key encrypts new cookies
  cookie: {
    httpOnly: true,
    secure: false,        // Set to true on production with HTTPS
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60,      // 1 hour in seconds
    // domain: 'example.com' // Optional: restrict cookie to a specific domain
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Define your Passport strategy here, e.g.:
// passport.use(new SomeStrategy(...));

// ⚠️ Important: Only store minimal data in the session (e.g., user ID).
// Since it's saved in an encrypted cookie, storing too much will increase cookie size
// and slow down every request, including static file requests.

passport.serializeUser((user, done) => {
  done(null, { id: user.id, username: user.username }); // Avoid saving the full user object
});
passport.deserializeUser((user, done) => done(null, user));

// Middleware to check if authenticated
const ensureAuth = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

// Example routes
app.get('/', (req, res) => {
  res.send('<a href="/login">Login</a>');
});

app.get('/login', passport.authenticate('some-strategy'));

app.get('/profile', ensureAuth, (req, res) => {
  res.send(`
    <h1>Welcome ${req.user.username}</h1>
    <p>ID: ${req.user.id}</p>
    <p><a href="/logout">Logout</a></p>
  `);
});

app.get('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/');
  });
});

app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});
```

## API

### passportCookieSession(options)

Creates Express middleware for encrypted cookie sessions.

- options.name (string) – Cookie name (default: 'session').
- options.keys (string[]) – Array of secret keys used for encryption and decryption.  
  The first key is used to encrypt new cookies and also to decrypt them;  
  the remaining keys are only used to decrypt older cookies (supports key rotation).
- options.cookie (object) – Cookie options (see https://github.com/jshttp/cookie#options):

  - path (default '/')
  - httpOnly (default true)
  - secure (default false)
  - sameSite (default 'lax')
  - maxAge (in seconds, default 86400)
  - domain (optional)

## Security Notes

- In production, always serve your app over HTTPS and set secure: true in cookie options.
- Rotate your encryption keys regularly by providing multiple keys in keys.
- Sessions are encrypted and authenticated using AES-256-GCM for confidentiality and integrity.

## License

MIT © robodin08
