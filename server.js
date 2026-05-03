require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const passport   = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const path       = require('path');
const { Firestore } = require('@google-cloud/firestore');

const app  = express();
const PORT = process.env.PORT || 3000;

// Initialize Firestore using the Project ID from your environment variables
const firestore = new Firestore({
  projectId: process.env.GOOGLE_CLOUD_PROJECT,
  databaseId: process.env.FIRESTORE_DATABASE_ID
});

// Cloud Run (and any reverse proxy) forwards requests via HTTP internally.
// Without this, Express doesn't trust X-Forwarded-* headers, session cookies
// are flagged insecure, and get dropped — so every request looks unauthenticated.
app.set('trust proxy', 1);

// ── SESSION ───────────────────────────────────────────────────────────────────
const isProduction = process.env.NODE_ENV === 'production' || !!process.env.K_SERVICE;

// Parse JSON bodies for API requests
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: isProduction,   // send cookie only over HTTPS in prod / Cloud Run
    sameSite: 'lax',
  },
}));

// ── PASSPORT ──────────────────────────────────────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

const hasGoogleAuth = process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;

if (!hasGoogleAuth) {
  console.warn('\n  ℹ  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set — running in development mode (auth disabled)\n');
} else {
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
}

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  // In development mode (no Google auth), skip auth check and attach a mock user
  if (!hasGoogleAuth) {
    req.user = { id: 'dev-local', name: 'Local Developer' };
    return next();
  }
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

if (hasGoogleAuth) {
  app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
  );
}

if (hasGoogleAuth) {
  app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login?error=auth' }),
    (_req, res) => res.redirect('/')
  );
}

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/login'));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// ── FIRESTORE API ROUTES ──────────────────────────────────────────────────────

// GET all plans for the authenticated user
app.get('/api/plans', requireAuth, async (req, res) => {
  try {
    const snapshot = await firestore.collection('loan_plans').where('userId', '==', req.user.id).get();
    const plans = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(plans);
  } catch (err) {
    console.error('Error fetching plans:', err);
    res.status(500).json({ error: 'Failed to fetch plans' });
  }
});

// POST a new plan
app.post('/api/plans', requireAuth, async (req, res) => {
  try {
    // Validation: Disbursed cannot exceed sanctioned
    if (req.body.disbursedSoFar > req.body.sanctionedAmt) {
      return res.status(400).json({ error: 'Disbursed amount cannot exceed sanctioned amount.' });
    }

    // Check if a plan with the same name already exists for this user
    if (req.body.planName) {
      const existingSnapshot = await firestore.collection('loan_plans')
        .where('userId', '==', req.user.id)
        .where('planName', '==', req.body.planName)
        .limit(1)
        .get();
      if (!existingSnapshot.empty) {
        return res.status(400).json({ error: 'A plan with this name already exists.' });
      }
    }
    const planData = { 
      ...req.body, 
      userId: req.user.id, 
      createdAt: Firestore.FieldValue.serverTimestamp(),
      updatedAt: Firestore.FieldValue.serverTimestamp()
    };
    const docRef = await firestore.collection('loan_plans').add(planData);
    res.json({ id: docRef.id, ...planData });
  } catch (err) {
    console.error('Error saving plan:', err);
    res.status(500).json({ error: 'Failed to save plan' });
  }
});

// PUT (update) an existing plan
app.put('/api/plans/:id', requireAuth, async (req, res) => {
  try {
    const docRef = firestore.collection('loan_plans').doc(req.params.id);
    const doc = await docRef.get();
    
    // Security check: Make sure this plan belongs to the logged-in user
    if (!doc.exists || doc.data().userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Validation: Disbursed cannot exceed sanctioned
    if (req.body.disbursedSoFar > req.body.sanctionedAmt) {
      return res.status(400).json({ error: 'Disbursed amount cannot exceed sanctioned amount.' });
    }

    // Check for unique name if the planName is being updated
    if (req.body.planName && req.body.planName !== doc.data().planName) {
      const existingSnapshot = await firestore.collection('loan_plans')
        .where('userId', '==', req.user.id)
        .where('planName', '==', req.body.planName)
        .limit(1)
        .get();
      if (!existingSnapshot.empty) {
        return res.status(400).json({ error: 'A plan with this name already exists.' });
      }
    }
    
    const updateData = { ...req.body, updatedAt: Firestore.FieldValue.serverTimestamp() };
    delete updateData.userId; // Prevent hijacking ownership
    
    await docRef.update(updateData);
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating plan:', err);
    res.status(500).json({ error: 'Failed to update plan' });
  }
});

// DELETE a plan
app.delete('/api/plans/:id', requireAuth, async (req, res) => {
  try {
    const docRef = firestore.collection('loan_plans').doc(req.params.id);
    const doc = await docRef.get();
    
    if (!doc.exists || doc.data().userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    await docRef.delete();
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting plan:', err);
    res.status(500).json({ error: 'Failed to delete plan' });
  }
});

// POST a new transaction (ad-hoc prepayment)
app.post('/api/plans/:id/transactions', requireAuth, async (req, res) => {
  try {
    const planRef = firestore.collection('loan_plans').doc(req.params.id);
    const planDoc = await planRef.get();
    
    if (!planDoc.exists || planDoc.data().userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { amount, date } = req.body;
    const txData = {
      amount: parseFloat(amount),
      date: date || new Date().toISOString().split('T')[0],
      type: 'prepayment',
      createdAt: Firestore.FieldValue.serverTimestamp()
    };
    
    await planRef.collection('transactions').add(txData);
    
    // Automatically update the main plan's principal recovered
    const currentPrincipal = parseFloat(planDoc.data().principalPaid) || 0;
    await planRef.update({ principalPaid: currentPrincipal + txData.amount });
    
    res.json({ success: true, transaction: txData });
  } catch (err) {
    console.error('Error logging transaction:', err);
    res.status(500).json({ error: 'Failed to log transaction' });
  }
});

// GET all transactions for a specific plan
app.get('/api/plans/:id/transactions', requireAuth, async (req, res) => {
  try {
    const planRef = firestore.collection('loan_plans').doc(req.params.id);
    const planDoc = await planRef.get();
    
    if (!planDoc.exists || planDoc.data().userId !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const snapshot = await planRef.collection('transactions').orderBy('date', 'desc').get();
    const transactions = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(transactions);
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// ── MATH HELPERS FOR CRON ─────────────────────────────────────────────────────
function calcEMI(principal, annualRate, loanMonths) {
  if (principal <= 0 || loanMonths <= 0) return 0;
  const monthlyRate = annualRate / 100 / 12;
  if (monthlyRate === 0) return principal / loanMonths;
  return (principal * monthlyRate * Math.pow(1 + monthlyRate, loanMonths)) / (Math.pow(1 + monthlyRate, loanMonths) - 1);
}

function calcSchedule(rate, tranches, lumpsumAmt, disbursedAmt, principalPaid, emi) {
  let bal = disbursedAmt - principalPaid;
  const mr = rate / 100 / 12;
  let totInt = 0, months = 0;

  for (let m = 1; m <= 480; m++) {
    if (bal <= 0) break;
    let trancheTotal = 0;
    for (let t of (tranches || [])) { if (t.month === m) trancheTotal += (t.amt * 1e5); }
    bal += trancheTotal;
    
    const interest = bal * mr;
    let principal = emi - interest;
    if (principal < 0) principal = 0;
    if (principal > bal) principal = bal;

    let lumpsum = 0;
    if (lumpsumAmt > 0) { lumpsum = Math.min(lumpsumAmt, bal - principal); if (lumpsum < 0) lumpsum = 0; }

    totInt += interest;
    bal = bal - principal - lumpsum;
    months++;
    if (bal <= 0) break;
  }
  return { totalInterest: totInt, totalMonths: months };
}

// ── CRON JOB ROUTE (Triggered via Google Cloud Scheduler) ─────────────────────
app.post('/api/cron/monthly-emails', async (req, res) => {
  // Security: Only allow triggers that carry the secret authorization header
  const auth = req.headers['authorization'];
  const secret = process.env.CRON_SECRET || 'dev-secret';
  if (auth !== `Bearer ${secret}`) return res.status(403).json({ error: 'Unauthorized CRON trigger' });

  try {
    const snapshot = await firestore.collection('loan_plans').get();
    console.log(`\n[CRON] Starting Monthly Notification Job... Found ${snapshot.size} plans.`);
    
    for (const doc of snapshot.docs) {
      const p = doc.data();
      const disbursedAmt = p.disbursedSoFar || 0;
      const principalPaid = p.principalPaid || 0;
      if ((disbursedAmt - principalPaid) <= 0) continue; // Loan already closed

      const emi = calcEMI(disbursedAmt, p.interestRate, p.loanPeriod);
      const savings = Math.max(0, (p.monthlySalary || 0) - (p.monthlyExpenses || 0));
      const base = calcSchedule(p.interestRate, p.tranches, 0, disbursedAmt, principalPaid, emi);
      const opt = calcSchedule(p.interestRate, p.tranches, savings, disbursedAmt, principalPaid, emi);

      console.log(`-----------------------------------------------------`);
      console.log(`✉️ EMAIL TO: User ${p.userId}`);
      console.log(`   SUBJECT: Your Loan Snapshot - Save ₹${Math.round((base.totalInterest - opt.totalInterest)/100000)} Lakhs!`);
      console.log(`   BODY: Hi! Your EMI of ₹${Math.round(emi)} is coming up. You have ~₹${Math.round(savings)} in estimated savings this month.`);
      if (savings > 0) console.log(`   Action: Log a prepayment of ₹${Math.round(savings)} today to save ₹${Math.round(base.totalInterest - opt.totalInterest)} in future interest and finish ${base.totalMonths - opt.totalMonths} months early!`);
    }
    res.json({ success: true, message: 'Monthly emails processed successfully.' });
  } catch (err) { console.error('[CRON] Error:', err); res.status(500).json({ error: 'Internal Server Error' }); }
});

// ── PROTECTED STATIC FILES ────────────────────────────────────────────────────
app.use(requireAuth, express.static(path.join(__dirname, 'public')));

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  Loan Repayment Planner`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Running at http://localhost:${PORT}`);
  console.log(`  Mode: ${isProduction ? 'production' : 'development'}`);
  console.log(`  Callback URL: ${process.env.CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`}`);
  console.log(`  Press Ctrl+C to stop\n`);
});