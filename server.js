require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const passport   = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SESSION ───────────────────────────────────────────────────────────────────
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 },
}));

// ── PASSPORT ──────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy(
  {
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  process.env.CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`,
  },
  (_access, _refresh, profile, done) => {
    done(null, {
      id:    profile.id,
      name:  profile.displayName,
      email: profile.emails?.[0]?.value,
      photo: profile.photos?.[0]?.value,
    });
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (_req, res) => res.redirect('/')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// ── PROTECTED STATIC FILES ────────────────────────────────────────────────────
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  Loan Repayment Planner`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Running at http://localhost:${PORT}`);
  console.log(`  Press Ctrl+C to stop\n`);
});
