import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { User, StudyEvent, FriendRequest, Message, Report, Challenge, Quiz, QuizAttempt } from './models.js';
import { USERNAME_RE, EMAIL_RE, cleanText, normaliseUsername, normaliseEmail, parseYoutubeResource, computePoints, clampEventSeconds, MAX_DAILY_STUDY_SECONDS, applyDailyCaps } from './domain.js';
import { calculateQuizScore, rankQuizResults } from './quiz-domain.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const app = express();
const production = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: production ? [] : null } } }));
const configuredOrigins = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({
  origin(origin, callback) {
    if (!origin || configuredOrigins.includes(origin) || origin === (process.env.PUBLIC_APP_URL || process.env.RENDER_EXTERNAL_URL)) return callback(null, true);
    if (process.env.ALLOW_EXTENSION_ORIGINS === 'true' && /^chrome-extension:\/\/[a-p]{32}$/.test(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS. Set CORS_ORIGINS to your web app origin.'), false);
  },
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));
app.use(express.json({ limit: '256kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use((req, _res, next) => { req.body ||= {}; next(); });
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many authentication attempts. Please try again later.' } }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Rate limit reached. Please slow down.' } }));

const tokenSecret = () => {
  const secret = process.env.JWT_SECRET || (production ? '' : 'local-development-only-change-this-secret-000000');
  if (production && secret.length < 32) throw new Error('JWT_SECRET must be at least 32 characters in production.');
  return secret;
};
const signToken = user => jwt.sign({ sub: String(user._id), username: user.username, ver: Number(user.tokenVersion) || 0 }, tokenSecret(), { expiresIn: process.env.JWT_EXPIRES_IN || '7d', issuer: 'study-lock', audience: 'study-lock-users' });
const publicUser = (user, viewerId = null) => {
  const isSelf = viewerId && String(user._id) === String(viewerId);
  return {
    id: String(user._id), username: user.username, displayName: user.displayName,
    phoneNumber: isSelf ? (user.phoneNumber || '') : undefined,
    quickLinks: isSelf ? (user.quickLinks || []) : undefined,
    quickLinksConfigured: isSelf ? Boolean(user.quickLinksConfigured) : undefined,
    bio: user.bio || '', avatarUrl: user.avatarUrl || '', interests: user.interests || [], learningGoals: user.learningGoals || [],
    privacy: isSelf ? user.privacy : undefined,
    isAdmin: isSelf ? user.role === 'admin' : undefined,
    emailVerified: isSelf ? Boolean(user.emailVerified) : undefined,
    achievements: (isSelf || user.privacy?.showStudyStats) ? (user.achievements || []) : undefined, createdAt: user.createdAt,
    friendsCount: (isSelf || user.privacy?.showStudyStats) ? (user.friends || []).length : undefined
  };
};
async function computeChallengeProgress(challenge, userId) {
  const start = new Date(challenge.startsAt || challenge.createdAt || 0);
  const end = new Date(Math.min(Date.now(), new Date(challenge.endsAt).getTime()));
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end < start) return 0;
  const events = await StudyEvent.find({ userId, eventAt: { $gte: start, $lte: end } }).select('qualifyingSeconds completed eventAt').sort({ eventAt: 1 }).lean();
  const capped = applyDailyCaps(events);
  if (challenge.type === 'lessons') return capped.filter(e => e.acceptedCompletion).length;
  if (challenge.type === 'streak') {
    const days = [...new Set(capped.filter(e => e.acceptedSeconds > 0).map(e => e.day))].sort();
    let best = 0; let current = 0; let previous = null;
    for (const day of days) {
      const date = new Date(`${day}T00:00:00.000Z`);
      const expected = previous ? new Date(new Date(previous).getTime() + 86400_000) : null;
      current = previous && date.getTime() === expected.getTime() ? current + 1 : 1;
      best = Math.max(best, current); previous = day;
    }
    return best;
  }
  return Math.floor(capped.reduce((sum, e) => sum + e.acceptedSeconds, 0) / 60);
}
async function refreshChallengeProgress(userId) {
  const now = new Date();
  const challenges = await Challenge.find({ endsAt: { $gte: now }, startsAt: { $lte: now }, 'participants.userId': userId }).limit(100);
  for (const challenge of challenges) {
    const participant = challenge.participants.find(p => String(p.userId) === String(userId));
    if (!participant) continue;
    const progress = await computeChallengeProgress(challenge, userId);
    participant.progress = Math.max(participant.progress, progress);
    if (participant.progress >= challenge.goal && !participant.completedAt) participant.completedAt = new Date();
    await challenge.save();
  }
}

const auth = async (req, res, next) => {
  try {
    const header = String(req.headers.authorization || '');
    if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Sign in to continue.' });
    const payload = jwt.verify(header.slice(7), tokenSecret(), { issuer: 'study-lock', audience: 'study-lock-users' });
    const user = await User.findById(payload.sub).select('+email');
    if (!user) return res.status(401).json({ error: 'This account no longer exists.' });
    if ((Number(payload.ver) || 0) !== (Number(user.tokenVersion) || 0)) return res.status(401).json({ error: 'Your session has been revoked. Please sign in again.' });
    if (user.suspended) return res.status(403).json({ error: 'This account is suspended. Contact the Study Lock moderator team if you believe this is an error.' });
    req.user = user;
    User.updateOne({ _id: user._id, lastActiveAt: { $lt: new Date(Date.now() - 10 * 60_000) } }, { $set: { lastActiveAt: new Date() } }).catch(() => {});
    next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError) return res.status(401).json({ error: 'Your session expired. Please sign in again.' });
    next(error);
  }
};
const idIsValid = id => mongoose.isValidObjectId(id);
const sendError = (res, status, error) => res.status(status).json({ error });
const areFriends = (a, b) => (a.friends || []).some(id => String(id) === String(b._id));
const isBlocked = (a, b) => (a.blockedUsers || []).some(id => String(id) === String(b._id)) || (b.blockedUsers || []).some(id => String(id) === String(a._id));
const friendGuard = async (req, res, next) => {
  try {
    const other = await User.findById(req.params.userId || req.params.id);
    if (!idIsValid(req.params.userId || req.params.id)) return sendError(res, 400, 'Invalid user ID.');
    if (!other) return sendError(res, 404, 'User not found.');
    if (!areFriends(req.user, other)) return sendError(res, 403, 'You must be friends to use this feature.');
    if (isBlocked(req.user, other)) return sendError(res, 403, 'This connection is unavailable.');
    req.otherUser = other; next();
  } catch (error) { next(error); }
};

app.get('/health', (_req, res) => { const connected = mongoose.connection.readyState === 1; const payload = { ok: connected || process.env.NODE_ENV !== 'production', service: 'study-lock-social', version: '1.1.0', database: connected ? 'connected' : 'disconnected', timestamp: new Date().toISOString() }; res.status(payload.ok ? 200 : 503).json(payload); });
app.get('/api', (_req, res) => res.json({ name: 'Study Lock Social API', version: '1.1.0', docs: '/api/docs', health: '/health' }));
app.get('/api/docs', (_req, res) => res.json({ version: '1.1.0', endpoints: { auth: ['POST /api/auth/register (phoneNumber required; phone is not verified)', 'POST /api/auth/login', 'POST /api/auth/logout', 'POST /api/auth/resend-verification', 'POST /api/auth/forgot-password', 'POST /api/auth/reset-password', 'GET /api/auth/verify'], profile: ['GET/PATCH /api/me (profile and personal quickLinks)', 'DELETE /api/me', 'GET /api/users', 'GET /api/users/:username'], learning: ['POST /api/study-events', 'GET /api/me/stats', 'GET /api/leaderboard'], friends: ['GET /api/friends', 'POST /api/friends/requests', 'GET /api/friends/requests', 'POST /api/friends/requests/:id/accept', 'DELETE /api/friends/:userId', 'POST/DELETE /api/blocks/:userId'], messaging: ['GET/POST /api/conversations/:userId/messages'], challenges: ['GET/POST /api/challenges', 'POST /api/challenges/:id/join', 'POST /api/challenges/:id/progress', 'GET /api/admin/challenges', 'PATCH/DELETE /api/admin/challenges/:id'], quizzes: ['GET /api/quizzes', 'POST /api/admin/quizzes', 'GET /api/admin/quizzes', 'PATCH/DELETE /api/admin/quizzes/:id', 'POST /api/quizzes/:id/start', 'GET /api/quizzes/:id/attempt', 'PUT /api/quizzes/:id/attempt', 'POST /api/quizzes/:id/submit', 'GET /api/quizzes/:id/leaderboard (after scheduled end)', 'GET /api/admin/quizzes/:quizId/attempts/:attemptId/profile', 'PATCH /api/admin/quizzes/:quizId/attempts/:attemptId/prize', 'POST /api/quizzes/:id/prize/confirm'], safety: ['POST /api/reports', 'GET/PATCH /api/admin/reports', 'PATCH /api/admin/users/:id/suspension', 'DELETE /api/admin/messages/:id'] } }));

async function sendEmail({ to, subject, text, html }) {
  if (!process.env.EMAIL_API_KEY || !process.env.EMAIL_FROM) throw new Error('Email provider is not configured.');
  const response = await fetch(process.env.EMAIL_API_URL || 'https://api.resend.com/emails', {
    method: 'POST', headers: { 'Authorization': `Bearer ${process.env.EMAIL_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.EMAIL_FROM, to: [to], subject, text, html }), signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Email provider returned ${response.status}.`);
}
app.get('/api/auth/verify', async (req, res, next) => {
  try {
    const token = cleanText(req.query.token, 200);
    if (!/^[a-f0-9]{64}$/.test(token)) return sendError(res, 400, 'This verification link is invalid.');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ emailVerificationTokenHash: tokenHash, emailVerificationExpiresAt: { $gt: new Date() } }).select('+emailVerificationTokenHash +emailVerificationExpiresAt');
    if (!user) return sendError(res, 400, 'This verification link has expired or was already used. Request a new link by contacting support.');
    user.emailVerified = true; user.emailVerificationTokenHash = undefined; user.emailVerificationExpiresAt = undefined; await user.save();
    const base = process.env.PUBLIC_APP_URL || process.env.RENDER_EXTERNAL_URL || '/';
    return res.redirect(`${base.replace(/\/$/, '')}/?verified=1`);
  } catch (error) { next(error); }
});
app.post('/api/auth/resend-verification', async (req, res, next) => {
  try {
    const email = normaliseEmail(req.body.email);
    const response = { ok: true, message: 'If an unverified account exists for that email, a verification link will be sent.' };
    if (!EMAIL_RE.test(email) || !process.env.EMAIL_API_KEY || !process.env.EMAIL_FROM) return res.json(response);
    const user = await User.findOne({ email, emailVerified: false }).select('+emailVerificationTokenHash +emailVerificationExpiresAt');
    if (!user) return res.json(response);
    const token = crypto.randomBytes(32).toString('hex'); user.emailVerificationTokenHash = crypto.createHash('sha256').update(token).digest('hex'); user.emailVerificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); await user.save();
    const base = process.env.PUBLIC_APP_URL || process.env.RENDER_EXTERNAL_URL || '';
    const link = `${base.replace(/\/$/, '')}/api/auth/verify?token=${token}`;
    try { await sendEmail({ to: email, subject: 'Verify your Study Lock Social account', text: `Verify your email within 24 hours: ${link}`, html: `<p><a href="${link}">Verify your email address</a>. This link expires in 24 hours.</p>` }); } catch (error) { console.error('Verification resend failed:', error.message); }
    res.json(response);
  } catch (error) { next(error); }
});

app.post('/api/auth/forgot-password', async (req, res, next) => {
  try {
    const email = normaliseEmail(req.body.email);
    // Avoid disclosing whether an account exists.
    const response = { ok: true, message: 'If an account exists for that email, reset instructions will be sent.' };
    if (!EMAIL_RE.test(email) || !process.env.EMAIL_API_KEY || !process.env.EMAIL_FROM) return res.json(response);
    const user = await User.findOne({ email }).select('+passwordResetTokenHash +passwordResetExpiresAt');
    if (!user) return res.json(response);
    const token = crypto.randomBytes(32).toString('hex'); user.passwordResetTokenHash = crypto.createHash('sha256').update(token).digest('hex'); user.passwordResetExpiresAt = new Date(Date.now() + 60 * 60 * 1000); await user.save();
    const base = process.env.PUBLIC_APP_URL || process.env.RENDER_EXTERNAL_URL || '';
    const link = `${base.replace(/\/$/, '')}/?resetToken=${token}`;
    try { await sendEmail({ to: email, subject: 'Reset your Study Lock Social password', text: `Reset your password within one hour: ${link}`, html: `<p><a href="${link}">Reset your password</a>. This link expires in one hour.</p>` }); }
    catch (error) { console.error('Password reset email failed:', error.message); }
    res.json(response);
  } catch (error) { next(error); }
});
app.post('/api/auth/reset-password', async (req, res, next) => {
  try {
    const token = cleanText(req.body.token, 200); const password = String(req.body.password || '');
    if (!/^[a-f0-9]{64}$/.test(token)) return sendError(res, 400, 'Reset token is invalid.');
    if (password.length < 10 || Buffer.byteLength(password, 'utf8') > 72 || !/[a-z]/i.test(password) || !/\d/.test(password)) return sendError(res, 400, 'Password must be at least 10 characters, at most 72 UTF-8 bytes, and contain at least one letter and one number.');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ passwordResetTokenHash: hash, passwordResetExpiresAt: { $gt: new Date() } }).select('+passwordResetTokenHash +passwordResetExpiresAt');
    if (!user) return sendError(res, 400, 'Reset token has expired or was already used.');
    user.passwordHash = await bcrypt.hash(password, 12); user.tokenVersion = (Number(user.tokenVersion) || 0) + 1; user.passwordResetTokenHash = undefined; user.passwordResetExpiresAt = undefined; await user.save();
    res.json({ ok: true, message: 'Password updated. Sign in with the new password.' });
  } catch (error) { next(error); }
});

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const email = normaliseEmail(req.body.email); const username = normaliseUsername(req.body.username); const password = String(req.body.password || '');
    const phoneNumber = cleanText(req.body.phoneNumber, 20).replace(/[\s().-]/g, '');
    const displayName = cleanText(req.body.displayName || username, 60);
    if (req.body.acceptTerms !== true) return sendError(res, 400, 'Please accept the community rules and privacy notice before creating an account.');
    if (!EMAIL_RE.test(email)) return sendError(res, 400, 'Enter a valid email address.');
    if (!/^\+?[1-9]\d{6,14}$/.test(phoneNumber)) return sendError(res, 400, 'Enter a valid phone number with 7–15 digits, including country code if needed. The phone number is not verified.');
    if (!USERNAME_RE.test(username)) return sendError(res, 400, 'Username must be 3–24 characters and use only letters, numbers, or underscores.');
    if (password.length < 10 || Buffer.byteLength(password, 'utf8') > 72 || !/[a-z]/i.test(password) || !/\d/.test(password)) return sendError(res, 400, 'Password must be at least 10 characters, at most 72 UTF-8 bytes, and contain at least one letter and one number.');
    if (displayName.length < 1) return sendError(res, 400, 'Display name is required.');
    const duplicate = await User.findOne({ $or: [{ email }, { username }] }).select('+email');
    if (duplicate) return sendError(res, 409, duplicate.email === email ? 'An account with this email already exists.' : 'That username is already taken.');
    const passwordHash = await bcrypt.hash(password, 12);
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(normaliseEmail).filter(Boolean);
    const requireVerification = process.env.NODE_ENV === 'production' || process.env.REQUIRE_EMAIL_VERIFICATION === 'true';
    let verificationToken = null;
    const userFields = { email, username, displayName, phoneNumber, passwordHash, role: adminEmails.includes(email) ? 'admin' : 'user', emailVerified: !requireVerification, privacy: { showOnLeaderboard: req.body.joinLeaderboard === true, showStudyStats: false } };
    if (requireVerification) {
      if (!process.env.EMAIL_API_KEY || !process.env.EMAIL_FROM) return sendError(res, 503, 'Account verification email is not configured on this deployment. Please contact the site administrator.');
      verificationToken = crypto.randomBytes(32).toString('hex');
      userFields.emailVerificationTokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');
      userFields.emailVerificationExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    }
    const user = await User.create(userFields);
    if (requireVerification) {
      const base = process.env.PUBLIC_APP_URL || process.env.RENDER_EXTERNAL_URL || '';
      const link = `${base.replace(/\/$/, '')}/api/auth/verify?token=${verificationToken}`;
      try { await sendEmail({ to: email, subject: 'Verify your Study Lock Social account', text: `Welcome to Study Lock Social. Verify your email within 24 hours: ${link}`, html: `<p>Welcome to Study Lock Social.</p><p><a href="${link}">Verify your email address</a>. This link expires in 24 hours.</p>` }); }
      catch (error) { await user.deleteOne(); console.error('Verification email failed:', error.message); return sendError(res, 503, 'Could not send verification email. Check the configured email provider and try again.'); }
      return res.status(201).json({ verificationRequired: true, message: 'Account created. Check your inbox for an email verification link before signing in.' });
    }
    return res.status(201).json({ token: signToken(user), user: publicUser(user, user._id) });
  } catch (error) { if (error?.code === 11000) return sendError(res, 409, 'That email or username is already taken.'); next(error); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const emailOrUsername = cleanText(req.body.emailOrUsername || req.body.email || req.body.username, 254).toLowerCase();
    const password = String(req.body.password || '');
    if (!emailOrUsername || !password) return sendError(res, 400, 'Enter your email/username and password.');
    if (Buffer.byteLength(password, 'utf8') > 72) return sendError(res, 401, 'Incorrect email/username or password.');
    const query = emailOrUsername.includes('@') ? { email: emailOrUsername } : { username: emailOrUsername };
    const user = await User.findOne(query).select('+passwordHash +email');
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return sendError(res, 401, 'Incorrect email/username or password.');
    if ((process.env.NODE_ENV === 'production' || process.env.REQUIRE_EMAIL_VERIFICATION === 'true') && !user.emailVerified) return sendError(res, 403, 'Please verify your email address before signing in.');
    return res.json({ token: signToken(user), user: publicUser(user, user._id) });
  } catch (error) { next(error); }
});
app.post('/api/auth/logout', auth, async (req, res, next) => { try { await User.updateOne({ _id: req.user._id }, { $inc: { tokenVersion: 1 } }); res.json({ ok: true, message: 'Signed out. Existing sessions are revoked.' }); } catch (error) { next(error); } });
app.get('/api/me', auth, async (req, res) => res.json({ user: publicUser(req.user, req.user._id), email: req.user.email }));
app.patch('/api/me', auth, async (req, res, next) => {
  try {
    const allowed = {};
    if (req.body.displayName !== undefined) { const value = cleanText(req.body.displayName, 60); if (!value) return sendError(res, 400, 'Display name cannot be empty.'); allowed.displayName = value; }
    if (req.body.bio !== undefined) allowed.bio = cleanText(req.body.bio, 400);
    if (req.body.phoneNumber !== undefined) { const value = cleanText(req.body.phoneNumber, 20).replace(/[\s().-]/g, ''); if (!/^\+?[1-9]\d{6,14}$/.test(value)) return sendError(res, 400, 'Enter a valid phone number with 7–15 digits, including country code if needed.'); allowed.phoneNumber = value; }
    if (req.body.quickLinks !== undefined) {
      if (!Array.isArray(req.body.quickLinks) || req.body.quickLinks.length > 10) return sendError(res, 400, 'Quick links must be a list of up to 10 websites.');
      const links = []; const seenUrls = new Set();
      for (const item of req.body.quickLinks) {
        const label = cleanText(item?.label, 30); const urlText = cleanText(item?.url, 500); const icon = cleanText(item?.icon || '🔗', 12);
        let parsed; try { parsed = new URL(urlText); } catch { return sendError(res, 400, 'Every quick link must have a valid HTTPS URL.'); }
        if (!label || parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) return sendError(res, 400, 'Quick links need a label and a safe HTTPS website URL.');
        const canonical = parsed.toString(); if (seenUrls.has(canonical)) return sendError(res, 400, 'Duplicate quick links are not allowed.'); seenUrls.add(canonical); links.push({ label, url: canonical, icon });
      }
      allowed.quickLinks = links; allowed.quickLinksConfigured = true;
    }
    if (req.body.avatarUrl !== undefined) {
      const value = cleanText(req.body.avatarUrl, 500);
      if (value && (!/^https:\/\//i.test(value) || !/^https:\/\/(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:\/.*)?$/i.test(value))) return sendError(res, 400, 'Avatar URL must be a valid HTTPS URL.');
      allowed.avatarUrl = value;
    }
    for (const key of ['interests', 'learningGoals']) if (req.body[key] !== undefined) {
      if (!Array.isArray(req.body[key])) return sendError(res, 400, `${key} must be a list.`);
      allowed[key] = [...new Set(req.body[key].map(x => cleanText(x, 50)).filter(Boolean))].slice(0, 20);
    }
    if (req.body.privacy !== undefined) {
      const p = req.body.privacy; const nextPrivacy = { ...req.user.privacy.toObject() };
      if (['public', 'friends', 'private'].includes(p.profileVisibility)) nextPrivacy.profileVisibility = p.profileVisibility;
      for (const key of ['showOnLeaderboard', 'showStudyStats', 'allowFriendRequests']) if (typeof p[key] === 'boolean') nextPrivacy[key] = p[key];
      if (['friends', 'none'].includes(p.allowMessages)) nextPrivacy.allowMessages = p.allowMessages;
      allowed.privacy = nextPrivacy;
    }
    const user = await User.findByIdAndUpdate(req.user._id, { $set: allowed }, { new: true, runValidators: true }).select('+email');
    res.json({ user: publicUser(user, user._id), email: user.email });
  } catch (error) { next(error); }
});
app.delete('/api/me', auth, async (req, res, next) => {
  try {
    const pass = String(req.body.password || '');
    const fullUser = await User.findById(req.user._id).select('+passwordHash +email');
    if (!await bcrypt.compare(pass, fullUser.passwordHash)) return sendError(res, 401, 'Password confirmation did not match.');
    const uid = req.user._id;
    const ownedQuizIds = await Quiz.find({ creatorId: uid }).distinct('_id');
    await Promise.all([
      User.updateMany({ friends: uid }, { $pull: { friends: uid } }), User.updateMany({ blockedUsers: uid }, { $pull: { blockedUsers: uid } }),
      User.deleteOne({ _id: uid }), StudyEvent.deleteMany({ userId: uid }), FriendRequest.deleteMany({ $or: [{ fromUserId: uid }, { toUserId: uid }] }),
      Message.deleteMany({ $or: [{ senderId: uid }, { recipientId: uid }] }), Report.deleteMany({ reporterId: uid }), Challenge.deleteMany({ creatorId: uid }), Challenge.updateMany({ 'participants.userId': uid }, { $pull: { participants: { userId: uid } } }),
      Quiz.deleteMany({ creatorId: uid }), QuizAttempt.deleteMany({ $or: [{ userId: uid }, { quizId: { $in: ownedQuizIds } }] }), Quiz.updateMany({ participantIds: uid }, { $pull: { participantIds: uid } })
    ]);
    res.json({ ok: true, message: 'Account and associated personal data deleted.' });
  } catch (error) { next(error); }
});

app.get('/api/users', auth, async (req, res, next) => {
  try {
    const q = cleanText(req.query.q, 80); const filter = { _id: { $ne: req.user._id }, 'privacy.profileVisibility': 'public', 'privacy.allowFriendRequests': true, blockedUsers: { $ne: req.user._id } };
    if (q) filter.$or = [{ username: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }, { displayName: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }];
    const users = await User.find(filter).sort({ lastActiveAt: -1 }).limit(30);
    res.json({ users: users.filter(u => !isBlocked(req.user, u)).map(u => ({ ...publicUser(u), isFriend: areFriends(req.user, u), pendingRequest: false })) });
  } catch (error) { next(error); }
});
app.get('/api/users/:username', auth, async (req, res, next) => {
  try {
    const user = await User.findOne({ username: normaliseUsername(req.params.username) });
    if (!user) return sendError(res, 404, 'User not found.');
    const self = String(user._id) === String(req.user._id); const friends = areFriends(req.user, user);
    if (!self && user.privacy.profileVisibility === 'private') return sendError(res, 404, 'User not found.');
    if (!self && user.privacy.profileVisibility === 'friends' && !friends) return sendError(res, 403, 'This profile is visible to friends only.');
    if (!self && isBlocked(req.user, user)) return sendError(res, 404, 'User not found.');
    const profile = publicUser(user, self ? user._id : null);
    if (!self && !user.privacy.showStudyStats) { delete profile.achievements; delete profile.friendsCount; }
    res.json({ user: profile, isSelf: self, isFriend: friends });
  } catch (error) { next(error); }
});

app.get('/api/users/:username/stats', auth, async (req, res, next) => {
  try {
    const user = await User.findOne({ username: normaliseUsername(req.params.username) });
    if (!user) return sendError(res, 404, 'User not found.');
    const self = String(user._id) === String(req.user._id); const friends = areFriends(req.user, user);
    if (!self && (user.privacy.profileVisibility === 'private' || (user.privacy.profileVisibility === 'friends' && !friends) || isBlocked(req.user, user))) return sendError(res, 404, 'User not found.');
    if (!self && !user.privacy.showStudyStats) return res.json({ statsVisible: false });
    const since = new Date(Date.now() - 30 * 86400_000);
    const raw = await StudyEvent.find({ userId: user._id, eventAt: { $gte: since } }).select('qualifyingSeconds completed eventAt videoId').sort({ eventAt: 1 }).lean();
    const events = applyDailyCaps(raw);
    res.json({ statsVisible: true, stats: { qualifyingSeconds: events.reduce((s, e) => s + e.acceptedSeconds, 0), completedLessons: events.filter(e => e.acceptedCompletion).length, activeDays: new Set(events.filter(e => e.acceptedSeconds > 0).map(e => e.day)).size, uniqueVideos: new Set(events.filter(e => e.acceptedSeconds > 0).map(e => e.videoId).filter(Boolean)).size } });
  } catch (error) { next(error); }
});

async function achievementKeys(userId, now = new Date()) {
  const since = new Date(now); since.setDate(since.getDate() - 365);
  const raw = await StudyEvent.find({ userId, eventAt: { $gte: since } }).select('qualifyingSeconds completed eventAt').sort({ eventAt: -1 }).lean();
  const events = applyDailyCaps(raw);
  const total = events.reduce((s, e) => s + e.acceptedSeconds, 0); const lessons = events.filter(e => e.acceptedCompletion).length;
  const activeDays = new Set(events.filter(e => e.acceptedSeconds > 0).map(e => e.day)).size;
  const badges = [];
  if (total >= 3600) badges.push('first-hour'); if (total >= 10 * 3600) badges.push('ten-hours'); if (total >= 50 * 3600) badges.push('fifty-hours');
  if (lessons >= 1) badges.push('first-lesson'); if (lessons >= 10) badges.push('ten-lessons'); if (activeDays >= 7) badges.push('consistent-week');
  await User.updateOne({ _id: userId }, { $addToSet: { achievements: { $each: badges } } });
  return { totalSeconds: total, completedLessons: lessons, activeDays, achievements: badges };
}
app.post('/api/study-events', auth, async (req, res, next) => {
  try {
    const list = Array.isArray(req.body.events) ? req.body.events.slice(0, 50) : [req.body];
    if (!list.length) return sendError(res, 400, 'At least one study event is required.');
    const accepted = []; const ignored = [];
    for (const item of list) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) { ignored.push({ eventId: '', reason: 'invalid-event' }); continue; }
      const eventId = cleanText(item.eventId, 100);
      if (!/^[A-Za-z0-9:_-]{8,100}$/.test(eventId)) { ignored.push({ eventId, reason: 'invalid-event-id' }); continue; }
      const resource = item.url ? parseYoutubeResource(item.url) : null;
      const videoId = cleanText(item.videoId || resource?.videoId || '', 20);
      if (videoId && !/^[A-Za-z0-9_-]{6,20}$/.test(videoId)) { ignored.push({ eventId, reason: 'invalid-video-id' }); continue; }
      const subject = cleanText(item.subject || 'general', 50).toLowerCase().replace(/[^a-z0-9 _-]/g, '') || 'general';
      const eventAtRaw = Number(item.eventAt) || Date.now();
      const eventAt = new Date(Math.min(Date.now() + 5 * 60_000, Math.max(Date.now() - 90 * 86400_000, eventAtRaw)));
      const doc = {
        userId: req.user._id, eventId, sessionId: cleanText(item.sessionId, 100), videoId,
        videoTitle: cleanText(item.videoTitle || 'YouTube lesson', 180), subject,
        qualifyingSeconds: clampEventSeconds(item.qualifyingSeconds), coverageSeconds: clampEventSeconds(item.coverageSeconds),
        completed: item.completed === true, eventAt
      };
      try { await StudyEvent.create(doc); accepted.push(eventId); }
      catch (error) { if (error?.code === 11000) ignored.push({ eventId, reason: 'duplicate' }); else throw error; }
    }
    const since = new Date(); since.setHours(0, 0, 0, 0);
    const today = await StudyEvent.find({ userId: req.user._id, eventAt: { $gte: since } }).select('qualifyingSeconds').lean();
    const daily = today.reduce((sum, item) => sum + item.qualifyingSeconds, 0);
    await refreshChallengeProgress(req.user._id);
    const stats = await achievementKeys(req.user._id);
    res.status(202).json({ ok: true, accepted: accepted.length, ignored, dailyQualifyingSeconds: Math.min(MAX_DAILY_STUDY_SECONDS, daily), stats });
  } catch (error) { next(error); }
});
app.get('/api/me/stats', auth, async (req, res, next) => {
  try {
    const days = Math.min(90, Math.max(1, Number(req.query.days) || 30)); const since = new Date(Date.now() - days * 86400_000);
    const raw = await StudyEvent.find({ userId: req.user._id, eventAt: { $gte: since } }).sort({ eventAt: -1 }).lean();
    const events = applyDailyCaps(raw); const byDay = new Map(); const videoSet = new Set(); let seconds = 0; let lessons = 0;
    for (const e of events) { byDay.set(e.day, (byDay.get(e.day) || 0) + e.acceptedSeconds); seconds += e.acceptedSeconds; if (e.videoId && e.acceptedSeconds > 0) videoSet.add(e.videoId); if (e.acceptedCompletion) lessons++; }
    const achievements = await achievementKeys(req.user._id);
    res.json({ stats: { days, qualifyingSeconds: seconds, completedEvents: lessons, uniqueVideos: videoSet.size, byDay: [...byDay].map(([date, seconds]) => ({ date, seconds: Math.min(MAX_DAILY_STUDY_SECONDS, seconds) })).sort((a,b)=>a.date.localeCompare(b.date)), achievements } });
  } catch (error) { next(error); }
});
app.get('/api/leaderboard', auth, async (req, res, next) => {
  try {
    const period = ['weekly', 'monthly', 'all-time'].includes(req.query.period) ? req.query.period : 'weekly';
    const now = new Date(); const from = period === 'weekly' ? new Date(now.getTime() - 7 * 86400_000) : period === 'monthly' ? new Date(now.getTime() - 30 * 86400_000) : new Date(0);
    const filter = { eventAt: { $gte: from } }; if (req.query.subject) filter.subject = cleanText(req.query.subject, 50).toLowerCase();
    // Aggregate in MongoDB rather than shipping a quarter-million event documents into the Node process.
    // For subject boards the daily cap applies to the selected subject; the overall board caps across subjects.
    const docs = await StudyEvent.aggregate([
      { $match: filter },
      { $group: { _id: { userId: '$userId', day: { $dateToString: { format: '%Y-%m-%d', date: '$eventAt', timezone: 'UTC' } }, subject: '$subject' }, seconds: { $sum: '$qualifyingSeconds' }, completed: { $sum: { $cond: ['$completed', 1, 0] } } } },
      { $group: { _id: { userId: '$_id.userId', day: '$_id.day' }, seconds: { $sum: '$seconds' }, completed: { $sum: '$completed' } } },
      { $project: { userId: '$_id.userId', day: '$_id.day', acceptedSeconds: { $min: ['$seconds', MAX_DAILY_STUDY_SECONDS] }, acceptedCompletions: { $min: ['$completed', 20] } } },
      { $group: { _id: '$userId', qualifyingSeconds: { $sum: '$acceptedSeconds' }, completedLessons: { $sum: '$acceptedCompletions' }, activeDays: { $sum: { $cond: [{ $gt: ['$acceptedSeconds', 0] }, 1, 0] } } } }
    ]).allowDiskUse(false);
    const ids = docs.map(row => row._id); const users = await User.find({ _id: { $in: ids }, 'privacy.showOnLeaderboard': true, 'privacy.profileVisibility': { $ne: 'private' } }).select('username displayName avatarUrl privacy achievements interests').lean();
    const userMap = new Map(users.map(u => [String(u._id), u])); const board = [];
    for (const row of docs) {
      const uid = String(row._id); const user = userMap.get(uid); if (!user) continue; if (user.privacy?.profileVisibility === 'friends' && !areFriends(req.user, { ...user, _id: uid })) continue;
      const qualifyingSeconds = row.qualifyingSeconds; const points = computePoints({ qualifyingSeconds, completedVideos: row.completedLessons, activeDays: row.activeDays });
      board.push({ user: { id: uid, username: user.username, displayName: user.displayName, avatarUrl: user.avatarUrl || '', achievements: user.privacy?.showStudyStats ? (user.achievements || []) : [] }, points, qualifyingSeconds, completedLessons: row.completedLessons, activeDays: row.activeDays });
    }
    board.sort((a,b) => b.points - a.points || b.qualifyingSeconds - a.qualifyingSeconds || a.user.username.localeCompare(b.user.username));
    res.json({ period, subject: req.query.subject || null, leaderboard: board.slice(0, 100).map((r,i) => ({ rank: i + 1, ...r })), myRank: board.findIndex(row => row.user.id === String(req.user._id)) + 1 || null, updatedAt: new Date().toISOString(), pointsFormula: '1 point per qualifying study minute + 20 per completed video event + 5 per active day' });
  } catch (error) { next(error); }
});

app.get('/api/friends', auth, async (req, res, next) => {
  try { const users = await User.find({ _id: { $in: req.user.friends || [] } }).sort({ username: 1 }); res.json({ friends: users.filter(u => !isBlocked(req.user, u)).map(u => publicUser(u)) }); }
  catch (error) { next(error); }
});
app.get('/api/friends/requests', auth, async (req, res, next) => {
  try {
    const [incoming, outgoing] = await Promise.all([
      FriendRequest.find({ toUserId: req.user._id, status: 'pending' }).sort({ createdAt: -1 }).populate('fromUserId', 'username displayName avatarUrl'),
      FriendRequest.find({ fromUserId: req.user._id, status: 'pending' }).sort({ createdAt: -1 }).populate('toUserId', 'username displayName avatarUrl')
    ]);
    res.json({ incoming: incoming.map(x => ({ id: x._id, from: publicUser(x.fromUserId), createdAt: x.createdAt })), outgoing: outgoing.map(x => ({ id: x._id, to: publicUser(x.toUserId), createdAt: x.createdAt })) });
  } catch (error) { next(error); }
});
app.post('/api/friends/requests', auth, async (req, res, next) => {
  try {
    const target = await User.findOne({ username: normaliseUsername(req.body.username || '') });
    if (!target) return sendError(res, 404, 'User not found.'); if (String(target._id) === String(req.user._id)) return sendError(res, 400, 'You cannot send yourself a friend request.');
    if (!target.privacy.allowFriendRequests || isBlocked(req.user, target)) return sendError(res, 403, 'Friend requests are not available for this user.');
    if (areFriends(req.user, target)) return sendError(res, 409, 'You are already friends.');
    const prior = await FriendRequest.findOne({ $or: [{ fromUserId: req.user._id, toUserId: target._id }, { fromUserId: target._id, toUserId: req.user._id }] });
    if (prior) { if (prior.status === 'pending' && String(prior.fromUserId) === String(target._id)) return sendError(res, 409, 'This user already sent you a request. Accept it from your incoming requests.'); if (prior.status === 'pending') return sendError(res, 409, 'A request is already pending.'); await prior.deleteOne(); }
    const request = await FriendRequest.create({ fromUserId: req.user._id, toUserId: target._id }); res.status(201).json({ request: { id: request._id, status: request.status, to: publicUser(target) } });
  } catch (error) { if (error?.code === 11000) return sendError(res, 409, 'A request is already pending.'); next(error); }
});
app.post('/api/friends/requests/:id/accept', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid friend-request ID.');
    const request = await FriendRequest.findOne({ _id: req.params.id, toUserId: req.user._id, status: 'pending' }); if (!request) return sendError(res, 404, 'Pending request not found.');
    const from = await User.findById(request.fromUserId); if (!from) return sendError(res, 404, 'Requester no longer exists.'); if (isBlocked(req.user, from)) return sendError(res, 403, 'This connection is unavailable.');
    await Promise.all([User.updateOne({ _id: req.user._id }, { $addToSet: { friends: from._id } }), User.updateOne({ _id: from._id }, { $addToSet: { friends: req.user._id } }), FriendRequest.updateOne({ _id: request._id }, { $set: { status: 'accepted', respondedAt: new Date() } })]);
    res.json({ ok: true, friend: publicUser(from) });
  } catch (error) { next(error); }
});
app.post('/api/friends/requests/:id/decline', auth, async (req, res, next) => {
  try { if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid friend-request ID.'); const r = await FriendRequest.findOneAndUpdate({ _id: req.params.id, toUserId: req.user._id, status: 'pending' }, { $set: { status: 'declined', respondedAt: new Date() } }, { new: true }); if (!r) return sendError(res, 404, 'Pending request not found.'); res.json({ ok: true }); }
  catch (error) { next(error); }
});
app.delete('/api/friends/:userId', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.userId)) return sendError(res, 400, 'Invalid user ID.'); const uid = new mongoose.Types.ObjectId(req.params.userId);
    await Promise.all([User.updateOne({ _id: req.user._id }, { $pull: { friends: uid } }), User.updateOne({ _id: uid }, { $pull: { friends: req.user._id } }), FriendRequest.deleteMany({ $or: [{ fromUserId: req.user._id, toUserId: uid }, { fromUserId: uid, toUserId: req.user._id }] })]); res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post('/api/blocks/:userId', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.userId) || String(req.user._id) === req.params.userId) return sendError(res, 400, 'Invalid user ID.'); const uid = new mongoose.Types.ObjectId(req.params.userId);
    await Promise.all([User.updateOne({ _id: req.user._id }, { $addToSet: { blockedUsers: uid }, $pull: { friends: uid } }), User.updateOne({ _id: uid }, { $pull: { friends: req.user._id } }), FriendRequest.deleteMany({ $or: [{ fromUserId: req.user._id, toUserId: uid }, { fromUserId: uid, toUserId: req.user._id }] })]); res.json({ ok: true });
  } catch (error) { next(error); }
});
app.delete('/api/blocks/:userId', auth, async (req, res, next) => { try { if (!idIsValid(req.params.userId)) return sendError(res, 400, 'Invalid user ID.'); await User.updateOne({ _id: req.user._id }, { $pull: { blockedUsers: new mongoose.Types.ObjectId(req.params.userId) } }); res.json({ ok: true }); } catch (error) { next(error); } });

app.get('/api/conversations/:userId/messages', auth, friendGuard, async (req, res, next) => {
  try {
    const before = req.query.before ? new Date(req.query.before) : new Date(); const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    const messages = await Message.find({ createdAt: { $lt: before }, $or: [{ senderId: req.user._id, recipientId: req.otherUser._id }, { senderId: req.otherUser._id, recipientId: req.user._id }] }).sort({ createdAt: -1 }).limit(limit).lean();
    await Message.updateMany({ senderId: req.otherUser._id, recipientId: req.user._id, readAt: null }, { $set: { readAt: new Date() } });
    res.json({ messages: messages.reverse().map(m => ({ id: String(m._id), senderId: String(m.senderId), recipientId: String(m.recipientId), body: m.body, createdAt: m.createdAt, readAt: m.readAt || null })) });
  } catch (error) { next(error); }
});
app.post('/api/conversations/:userId/messages', auth, friendGuard, async (req, res, next) => {
  try {
    if (req.otherUser.privacy.allowMessages === 'none') return sendError(res, 403, 'This user has disabled messages.'); const body = cleanText(req.body.body, 2000); if (!body) return sendError(res, 400, 'Message cannot be empty.');
    const recent = await Message.countDocuments({ senderId: req.user._id, createdAt: { $gte: new Date(Date.now() - 60_000) } }); if (recent >= 20) return sendError(res, 429, 'Messaging rate limit reached. Try again in a minute.');
    const message = await Message.create({ senderId: req.user._id, recipientId: req.otherUser._id, body }); res.status(201).json({ message: { id: String(message._id), senderId: String(message.senderId), recipientId: String(message.recipientId), body: message.body, createdAt: message.createdAt } });
  } catch (error) { next(error); }
});
app.get('/api/conversations', auth, async (req, res, next) => {
  try {
    const ids = req.user.friends || []; const latest = await Message.find({ $or: [{ senderId: req.user._id, recipientId: { $in: ids } }, { recipientId: req.user._id, senderId: { $in: ids } }] }).sort({ createdAt: -1 }).limit(500).lean();
    const seen = new Set(); const entries = [];
    for (const m of latest) { const peerId = String(m.senderId) === String(req.user._id) ? String(m.recipientId) : String(m.senderId); if (seen.has(peerId) || req.user.blockedUsers.some(x => String(x) === peerId)) continue; seen.add(peerId); entries.push({ userId: peerId, lastMessage: { body: m.body, createdAt: m.createdAt, fromMe: String(m.senderId) === String(req.user._id) } }); }
    const users = await User.find({ _id: { $in: entries.map(x => x.userId) } }).select('username displayName avatarUrl'); const map = new Map(users.map(u => [String(u._id), publicUser(u)]));
    res.json({ conversations: entries.map(x => ({ user: map.get(x.userId), ...x })).filter(x => x.user) });
  } catch (error) { next(error); }
});

app.get('/api/challenges', auth, async (req, res, next) => {
  try {
    const now = new Date(); const challenges = await Challenge.find({ endsAt: { $gte: new Date(now.getTime() - 7 * 86400_000) }, $or: [{ visibility: 'public' }, { creatorId: req.user._id }, { 'participants.userId': req.user._id }, { visibility: 'friends', creatorId: { $in: req.user.friends || [] } }] }).sort({ endsAt: 1 }).limit(100).populate('creatorId', 'username displayName');
    res.json({ challenges: challenges.map(c => ({ id: String(c._id), title: c.title, description: c.description, type: c.type, goal: c.goal, startsAt: c.startsAt, endsAt: c.endsAt, visibility: c.visibility, creator: c.creatorId ? publicUser(c.creatorId) : null, participantCount: c.participants.length, joined: c.participants.some(p => String(p.userId) === String(req.user._id)), myProgress: c.participants.find(p => String(p.userId) === String(req.user._id))?.progress || 0 })) });
  } catch (error) { next(error); }
});
app.post('/api/challenges', auth, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 100); const description = cleanText(req.body.description, 500); const type = ['study_minutes', 'lessons', 'streak'].includes(req.body.type) ? req.body.type : 'study_minutes'; const goal = Math.floor(Number(req.body.goal)); const endsAt = new Date(req.body.endsAt);
    if (title.length < 3) return sendError(res, 400, 'Challenge title must be at least 3 characters.'); if (!Number.isFinite(goal) || goal < 1 || goal > 100000) return sendError(res, 400, 'Enter a valid challenge goal.');
    if (!Number.isFinite(endsAt.getTime()) || endsAt <= new Date() || endsAt > new Date(Date.now() + 90 * 86400_000)) return sendError(res, 400, 'Challenge end date must be in the next 90 days.');
    const visibility = req.body.visibility === 'friends' ? 'friends' : 'public'; const challenge = await Challenge.create({ creatorId: req.user._id, title, description, type, goal, endsAt, visibility, participants: [{ userId: req.user._id, progress: 0 }] });
    res.status(201).json({ challenge: { id: String(challenge._id), title, description, type, goal, endsAt, visibility, participantCount: 1, joined: true, myProgress: 0 } });
  } catch (error) { next(error); }
});
app.post('/api/challenges/:id/join', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid challenge ID.'); const challenge = await Challenge.findById(req.params.id); if (!challenge || challenge.endsAt < new Date()) return sendError(res, 404, 'Active challenge not found.');
    if (challenge.visibility === 'friends' && String(challenge.creatorId) !== String(req.user._id)) { const owner = await User.findById(challenge.creatorId); if (!owner || !areFriends(req.user, owner)) return sendError(res, 403, 'This challenge is for friends only.'); }
    const exists = challenge.participants.some(p => String(p.userId) === String(req.user._id)); if (!exists) { challenge.participants.push({ userId: req.user._id, progress: 0 }); await challenge.save(); }
    const participant = challenge.participants.find(p => String(p.userId) === String(req.user._id));
    participant.progress = Math.max(participant.progress, await computeChallengeProgress(challenge, req.user._id));
    if (participant.progress >= challenge.goal && !participant.completedAt) participant.completedAt = new Date();
    await challenge.save();
    res.json({ ok: true, joined: true, participantCount: challenge.participants.length, progress: participant.progress });
  } catch (error) { next(error); }
});
app.post('/api/challenges/:id/progress', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid challenge ID.');
    const challenge = await Challenge.findOne({ _id: req.params.id, endsAt: { $gte: new Date() }, 'participants.userId': req.user._id });
    if (!challenge) return sendError(res, 404, 'Join an active challenge first.');
    const participant = challenge.participants.find(p => String(p.userId) === String(req.user._id));
    participant.progress = Math.max(participant.progress, await computeChallengeProgress(challenge, req.user._id));
    if (participant.progress >= challenge.goal && !participant.completedAt) participant.completedAt = new Date();
    await challenge.save();
    res.json({ ok: true, progress: participant.progress, goal: challenge.goal, completed: participant.progress >= challenge.goal, source: 'server-calculated from synced study events' });
  } catch (error) { next(error); }
});

const requireAdmin = (req, res, next) => req.user?.role === 'admin' ? next() : sendError(res, 403, 'Moderator access required.');

function normalizeQuizQuestions(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 100) throw new Error('A quiz must contain between 1 and 100 questions.');
  return input.map((raw, index) => {
    const prompt = cleanText(raw?.prompt, 1000);
    const type = ['single_choice', 'multiple_choice', 'true_false', 'short_answer'].includes(raw?.type) ? raw.type : null;
    const points = Math.floor(Number(raw?.points ?? 1));
    if (prompt.length < 3) throw new Error(`Question ${index + 1} needs a prompt of at least 3 characters.`);
    if (!type) throw new Error(`Question ${index + 1} has an unsupported type.`);
    if (!Number.isFinite(points) || points < 1 || points > 100) throw new Error(`Question ${index + 1} points must be between 1 and 100.`);
    let options = Array.isArray(raw.options) ? raw.options.map(x => cleanText(x, 200)).filter(Boolean) : [];
    let correctAnswers = Array.isArray(raw.correctAnswers) ? raw.correctAnswers.map(x => cleanText(x, 1000)).filter(Boolean) : [];
    if (type === 'true_false') { options = ['True', 'False']; correctAnswers = correctAnswers.map(x => /^true$/i.test(x) ? 'True' : /^false$/i.test(x) ? 'False' : x); }
    if (type === 'single_choice' || type === 'multiple_choice' || type === 'true_false') {
      options = [...new Map(options.map(x => [x.toLocaleLowerCase(), x])).values()];
      if (options.length < 2 || options.length > 12) throw new Error(`Question ${index + 1} needs 2–12 answer options.`);
      const optionLookup = new Map(options.map(x => [x.toLocaleLowerCase(), x]));
      correctAnswers = [...new Set(correctAnswers.map(x => optionLookup.get(x.toLocaleLowerCase())).filter(Boolean))];
      if (!correctAnswers.length || (type !== 'multiple_choice' && correctAnswers.length !== 1)) throw new Error(`Question ${index + 1} must have valid correct answer(s) that match its options.`);
    } else {
      options = [];
      correctAnswers = [...new Set(correctAnswers.map(x => x.trim()).filter(Boolean))];
      if (!correctAnswers.length) throw new Error(`Question ${index + 1} needs at least one accepted answer.`);
    }
    return { prompt, type, options, correctAnswers, points, explanation: cleanText(raw?.explanation, 1000) };
  });
}
function safeQuizQuestions(quiz) {
  return quiz.questions.map(q => ({ id: String(q._id), prompt: q.prompt, type: q.type, options: q.options || [], points: q.points }));
}
function quizWindow(quiz, now = new Date()) {
  if (now < new Date(quiz.startsAt)) return 'upcoming';
  if (now >= new Date(quiz.endsAt)) return 'ended';
  return 'open';
}
function quizDeadline(quiz, attempt) {
  return new Date(Math.min(new Date(quiz.endsAt).getTime(), new Date(attempt.startedAt).getTime() + Number(quiz.durationMinutes) * 60_000));
}
function cleanQuizAnswers(quiz, incoming) {
  const rawAnswers = Array.isArray(incoming) ? incoming : [];
  const answerMap = new Map();
  const questionMap = new Map(quiz.questions.map(q => [String(q._id), q]));
  for (const item of rawAnswers) {
    const id = cleanText(item?.questionId || item?.id, 50);
    const question = questionMap.get(id);
    if (!question) continue;
    const values = (Array.isArray(item.response) ? item.response : item.response === undefined || item.response === null ? [] : [item.response])
      .map(x => cleanText(x, question.type === 'short_answer' ? 1000 : 200)).filter(Boolean).slice(0, 12);
    if (question.type === 'single_choice' || question.type === 'true_false') {
      const found = values.find(v => (question.options || []).some(o => o.toLocaleLowerCase() === v.toLocaleLowerCase()));
      answerMap.set(id, found ? [(question.options || []).find(o => o.toLocaleLowerCase() === found.toLocaleLowerCase())] : []);
    } else if (question.type === 'multiple_choice') {
      const valid = [...new Set(values.map(v => (question.options || []).find(o => o.toLocaleLowerCase() === v.toLocaleLowerCase())).filter(Boolean))];
      answerMap.set(id, valid);
    } else answerMap.set(id, values.slice(0, 1));
  }
  return [...answerMap.entries()].map(([questionId, response]) => ({ questionId, response }));
}
async function finalizeQuizAttempt(quiz, attempt, { timedOut = false, now = new Date(), answers } = {}) {
  if (attempt.status !== 'in_progress') return attempt;
  if (answers !== undefined) attempt.answers = cleanQuizAnswers(quiz, answers);
  const deadline = quizDeadline(quiz, attempt);
  const submittedAt = timedOut ? deadline : now;
  const finalScore = calculateQuizScore(quiz.questions, attempt.answers);
  attempt.score = finalScore.score; attempt.totalPoints = finalScore.totalPoints;
  attempt.elapsedSeconds = Math.max(0, Math.floor((Math.min(submittedAt.getTime(), deadline.getTime()) - new Date(attempt.startedAt).getTime()) / 1000));
  attempt.submittedAt = submittedAt; attempt.status = timedOut ? 'timed_out' : 'submitted';
  await attempt.save();
  return attempt;
}
export async function sweepExpiredQuizAttempts() {
  if (mongoose.connection.readyState !== 1) return;
  const now = new Date();
  const inProgress = await QuizAttempt.find({ status: 'in_progress' }).limit(5000);
  const quizIds = [...new Set(inProgress.map(a => String(a.quizId)))];
  const quizDocs = quizIds.length ? await Quiz.find({ _id: { $in: quizIds } }) : [];
  const quizMap = new Map(quizDocs.map(q => [String(q._id), q]));
  for (const attempt of inProgress) {
    const quiz = quizMap.get(String(attempt.quizId));
    if (quiz && now.getTime() >= quizDeadline(quiz, attempt).getTime()) await finalizeQuizAttempt(quiz, attempt, { timedOut: true, now });
  }
  await Quiz.updateMany({ isPublished: true, endsAt: { $lte: now }, resultsFinalizedAt: { $exists: false } }, { $set: { resultsFinalizedAt: now } });
}
function quizSummary(quiz, attempt, now = new Date(), admin = false) {
  const state = quizWindow(quiz, now);
  return {
    id: String(quiz._id), title: quiz.title, description: quiz.description, startsAt: quiz.startsAt, endsAt: quiz.endsAt,
    durationMinutes: quiz.durationMinutes, maxParticipants: quiz.maxParticipants, participantCount: (quiz.participantIds || []).length,
    questionCount: quiz.questions.length, totalPoints: quiz.questions.reduce((sum, q) => sum + Number(q.points || 1), 0),
    state, isPublished: Boolean(quiz.isPublished), resultsPublished: state === 'ended',
    attempt: attempt ? { id: String(attempt._id), status: attempt.status, startedAt: attempt.startedAt, submittedAt: attempt.submittedAt, score: state === 'ended' ? attempt.score : undefined, prizeAwarded: Boolean(attempt.prizeAwarded), prizeAmount: attempt.prizeAwarded ? Number(attempt.prizeAmount || 0) : undefined, prizeReceived: Boolean(attempt.prizeReceived) } : null,
    canEdit: admin && !attempt
  };
}
async function quizLeaderboardRows(quiz, { admin = false } = {}) {
  const attempts = await QuizAttempt.find({ quizId: quiz._id, status: { $in: ['submitted', 'timed_out'] } }).populate('userId', 'username displayName avatarUrl bio interests learningGoals phoneNumber email privacy createdAt').lean();
  const rankedAttempts = rankQuizResults(attempts);
  return rankedAttempts.map(({ attempt: a, rank }) => {
    const user = a.userId || {};
    const row = { rank, attemptId: String(a._id), score: a.score, totalPoints: a.totalPoints, elapsedSeconds: a.elapsedSeconds, submittedAt: a.submittedAt, status: a.status,
      user: { id: String(user._id || ''), username: user.username || 'deleted-user', displayName: user.displayName || 'Deleted user', avatarUrl: user.avatarUrl || '' },
      prize: a.prizeReceived ? { amount: a.prizeAmount, note: a.prizeNote, receivedAt: a.prizeReceivedAt } : null };
    if (admin) { row.prizeAwarded = Boolean(a.prizeAwarded); row.prizeAmount = Number(a.prizeAmount || 0); row.prizeNote = a.prizeNote || ''; row.profileAvailable = Boolean(user._id); }
    return row;
  });
}

// Public list, personal attempts, and result board. Correct answers are never sent to learners.
app.get('/api/quizzes', auth, async (req, res, next) => {
  try {
    await sweepExpiredQuizAttempts();
    const now = new Date();
    const quizzes = await Quiz.find({ isPublished: true }).sort({ startsAt: -1 }).limit(200).lean();
    const attempts = await QuizAttempt.find({ userId: req.user._id, quizId: { $in: quizzes.map(q => q._id) } }).lean();
    const attemptMap = new Map(attempts.map(a => [String(a.quizId), a]));
    res.json({ quizzes: quizzes.map(q => quizSummary(q, attemptMap.get(String(q._id)), now, false)) });
  } catch (error) { next(error); }
});
app.get('/api/admin/quizzes', auth, requireAdmin, async (req, res, next) => {
  try {
    await sweepExpiredQuizAttempts();
    const quizzes = await Quiz.find().sort({ createdAt: -1 }).limit(200).lean();
    const attempts = await QuizAttempt.find({ quizId: { $in: quizzes.map(q => q._id) } }).lean();
    const attemptMap = new Map(); for (const a of attempts) { const k = String(a.quizId); if (!attemptMap.has(k)) attemptMap.set(k, []); attemptMap.get(k).push(a); }
    const now = new Date();
    res.json({ quizzes: quizzes.map(q => ({ ...quizSummary(q, null, now, true), questionDetails: q.questions.map(x => ({ id: String(x._id), prompt: x.prompt, type: x.type, options: x.options, correctAnswers: x.correctAnswers, points: x.points, explanation: x.explanation })), attemptCount: (attemptMap.get(String(q._id)) || []).length, isPublished: q.isPublished })) });
  } catch (error) { next(error); }
});
app.post('/api/admin/quizzes', auth, requireAdmin, async (req, res, next) => {
  try {
    const title = cleanText(req.body.title, 120); const description = cleanText(req.body.description, 1000);
    const startsAt = new Date(req.body.startsAt); const endsAt = new Date(req.body.endsAt);
    const durationMinutes = Math.floor(Number(req.body.durationMinutes)); const maxParticipants = Math.floor(Number(req.body.maxParticipants));
    if (title.length < 3) return sendError(res, 400, 'Quiz title must be at least 3 characters.');
    if (!Number.isFinite(startsAt.getTime()) || !Number.isFinite(endsAt.getTime()) || endsAt <= startsAt || endsAt <= new Date() || startsAt < new Date(Date.now() - 60_000)) return sendError(res, 400, 'Quiz dates must be valid, future-facing, and the end must follow the start.');
    if (endsAt.getTime() - startsAt.getTime() > 90 * 86400_000) return sendError(res, 400, 'A quiz window cannot exceed 90 days.');
    if (!Number.isInteger(durationMinutes) || durationMinutes < 1 || durationMinutes > 240) return sendError(res, 400, 'Quiz duration must be 1–240 minutes per participant.');
    if (!Number.isInteger(maxParticipants) || maxParticipants < 1 || maxParticipants > 10000) return sendError(res, 400, 'Maximum participants must be 1–10,000.');
    let questions; try { questions = normalizeQuizQuestions(req.body.questions); } catch (e) { return sendError(res, 400, e.message); }
    const quiz = await Quiz.create({ creatorId: req.user._id, title, description, startsAt, endsAt, durationMinutes, maxParticipants, isPublished: req.body.isPublished !== false, questions });
    res.status(201).json({ quiz: quizSummary(quiz, null, new Date(), true), message: 'Quiz created.' });
  } catch (error) { next(error); }
});
app.patch('/api/admin/quizzes/:id', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    const quiz = await Quiz.findById(req.params.id); if (!quiz) return sendError(res, 404, 'Quiz not found.');
    const attemptCount = await QuizAttempt.countDocuments({ quizId: quiz._id });
    if (attemptCount > 0) {
      if (Object.keys(req.body).length === 1 && typeof req.body.isPublished === 'boolean') {
        if (req.body.isPublished === false && quiz.isPublished) return sendError(res, 409, 'A quiz with participant attempts cannot be unpublished because that would hide its eventual public leaderboard.');
        quiz.isPublished = req.body.isPublished; await quiz.save(); return res.json({ quiz: quizSummary(quiz, null, new Date(), true), message: quiz.isPublished ? 'Quiz published.' : 'Quiz remains unpublished.' });
      }
      return sendError(res, 409, 'This quiz already has participants. Its questions and schedule are locked to preserve result integrity. Publishing visibility may be enabled, but a quiz with attempts cannot be hidden.');
    }
    const allowed = {};
    if (req.body.title !== undefined) { const v = cleanText(req.body.title, 120); if (v.length < 3) return sendError(res, 400, 'Quiz title must be at least 3 characters.'); allowed.title = v; }
    if (req.body.description !== undefined) allowed.description = cleanText(req.body.description, 1000);
    if (req.body.startsAt !== undefined) allowed.startsAt = new Date(req.body.startsAt);
    if (req.body.endsAt !== undefined) allowed.endsAt = new Date(req.body.endsAt);
    if (req.body.durationMinutes !== undefined) allowed.durationMinutes = Math.floor(Number(req.body.durationMinutes));
    if (req.body.maxParticipants !== undefined) allowed.maxParticipants = Math.floor(Number(req.body.maxParticipants));
    if (req.body.isPublished !== undefined) allowed.isPublished = req.body.isPublished === true;
    if (req.body.questions !== undefined) { try { allowed.questions = normalizeQuizQuestions(req.body.questions); } catch (e) { return sendError(res, 400, e.message); } }
    const startsAt = allowed.startsAt || quiz.startsAt; const endsAt = allowed.endsAt || quiz.endsAt;
    if (!Number.isFinite(new Date(startsAt).getTime()) || !Number.isFinite(new Date(endsAt).getTime()) || new Date(endsAt) <= new Date(startsAt) || new Date(endsAt) <= new Date()) return sendError(res, 400, 'Quiz dates must be valid, future-facing, and the end must follow the start.');
    if (new Date(endsAt) - new Date(startsAt) > 90 * 86400_000) return sendError(res, 400, 'A quiz window cannot exceed 90 days.');
    if (allowed.durationMinutes !== undefined && (!Number.isInteger(allowed.durationMinutes) || allowed.durationMinutes < 1 || allowed.durationMinutes > 240)) return sendError(res, 400, 'Quiz duration must be 1–240 minutes.');
    if (allowed.maxParticipants !== undefined && (!Number.isInteger(allowed.maxParticipants) || allowed.maxParticipants < 1 || allowed.maxParticipants > 10000)) return sendError(res, 400, 'Maximum participants must be 1–10,000.');
    Object.assign(quiz, allowed); await quiz.save();
    res.json({ quiz: quizSummary(quiz, null, new Date(), true), message: 'Quiz updated.' });
  } catch (error) { next(error); }
});
app.delete('/api/admin/quizzes/:id', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    const quiz = await Quiz.findByIdAndDelete(req.params.id); if (!quiz) return sendError(res, 404, 'Quiz not found.');
    await QuizAttempt.deleteMany({ quizId: quiz._id });
    res.json({ ok: true, message: 'Quiz and its attempts deleted.' });
  } catch (error) { next(error); }
});
app.post('/api/quizzes/:id/start', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    await sweepExpiredQuizAttempts();
    const quiz = await Quiz.findOne({ _id: req.params.id, isPublished: true }); if (!quiz) return sendError(res, 404, 'Quiz not found.');
    const now = new Date(); if (quizWindow(quiz, now) !== 'open') return sendError(res, 409, quizWindow(quiz, now) === 'upcoming' ? 'This quiz has not opened yet.' : 'This quiz has ended. Results are available on its leaderboard.');
    let attempt = await QuizAttempt.findOne({ quizId: quiz._id, userId: req.user._id });
    if (!attempt) {
      const reserved = await Quiz.findOneAndUpdate({ _id: quiz._id, isPublished: true, startsAt: { $lte: now }, endsAt: { $gt: now }, participantIds: { $ne: req.user._id }, $expr: { $lt: [{ $size: '$participantIds' }, '$maxParticipants'] } }, { $addToSet: { participantIds: req.user._id } }, { new: true });
      if (!reserved) { const latest = await Quiz.findById(quiz._id).select('participantIds maxParticipants endsAt'); if (latest && latest.participantIds.some(id => String(id) === String(req.user._id))) return sendError(res, 409, 'Your attempt is already reserved; refresh and continue.'); return sendError(res, 409, 'This quiz is full or no longer accepting participants.'); }
      try { attempt = await QuizAttempt.create({ quizId: quiz._id, userId: req.user._id, startedAt: now, totalPoints: quiz.questions.reduce((sum, q) => sum + Number(q.points || 1), 0) }); }
      catch (e) { await Quiz.updateOne({ _id: quiz._id }, { $pull: { participantIds: req.user._id } }); throw e; }
    }
    if (attempt.status !== 'in_progress') return sendError(res, 409, 'Your attempt is already submitted. Results publish at the quiz end time.');
    const deadline = quizDeadline(quiz, attempt); if (now >= deadline) { await finalizeQuizAttempt(quiz, attempt, { timedOut: true, now }); return sendError(res, 409, 'Your quiz time has ended. Your saved answers have been submitted.'); }
    res.json({ quiz: { id: String(quiz._id), title: quiz.title, durationMinutes: quiz.durationMinutes, endsAt: quiz.endsAt, deadlineAt: deadline, questions: safeQuizQuestions(quiz) }, attempt: { id: String(attempt._id), startedAt: attempt.startedAt, deadlineAt: deadline, answers: attempt.answers } });
  } catch (error) { next(error); }
});
app.get('/api/quizzes/:id/attempt', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    await sweepExpiredQuizAttempts();
    const quiz = await Quiz.findById(req.params.id); const attempt = await QuizAttempt.findOne({ quizId: req.params.id, userId: req.user._id });
    if (!quiz || !attempt) return sendError(res, 404, 'Quiz attempt not found.');
    if (attempt.status !== 'in_progress') return res.json({ submitted: true, attempt: quizSummary(quiz, attempt, new Date(), false).attempt, quiz: { id: String(quiz._id), title: quiz.title, state: quizWindow(quiz) } });
    const deadline = quizDeadline(quiz, attempt);
    res.json({ submitted: false, quiz: { id: String(quiz._id), title: quiz.title, durationMinutes: quiz.durationMinutes, endsAt: quiz.endsAt, deadlineAt: deadline, questions: safeQuizQuestions(quiz) }, attempt: { id: String(attempt._id), startedAt: attempt.startedAt, deadlineAt: deadline, answers: attempt.answers } });
  } catch (error) { next(error); }
});
app.put('/api/quizzes/:id/attempt', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    const quiz = await Quiz.findById(req.params.id); const attempt = await QuizAttempt.findOne({ quizId: req.params.id, userId: req.user._id, status: 'in_progress' });
    if (!quiz || !attempt) return sendError(res, 404, 'Active quiz attempt not found.');
    const now = new Date(); if (now >= quizDeadline(quiz, attempt)) { await finalizeQuizAttempt(quiz, attempt, { timedOut: true, now }); return sendError(res, 409, 'Time has ended. Your previously saved answers were submitted automatically.'); }
    attempt.answers = cleanQuizAnswers(quiz, req.body.answers); await attempt.save(); res.json({ ok: true, savedAt: new Date().toISOString() });
  } catch (error) { next(error); }
});
app.post('/api/quizzes/:id/submit', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    const quiz = await Quiz.findById(req.params.id); const attempt = await QuizAttempt.findOne({ quizId: req.params.id, userId: req.user._id });
    if (!quiz || !attempt) return sendError(res, 404, 'Quiz attempt not found.');
    if (attempt.status !== 'in_progress') return res.json({ ok: true, alreadySubmitted: true, status: attempt.status, resultsPublished: quizWindow(quiz) === 'ended' });
    const now = new Date(); const timedOut = now >= quizDeadline(quiz, attempt);
    await finalizeQuizAttempt(quiz, attempt, { timedOut, now, answers: timedOut ? undefined : req.body.answers });
    res.json({ ok: true, status: attempt.status, score: quizWindow(quiz) === 'ended' ? attempt.score : undefined, resultsPublished: quizWindow(quiz) === 'ended', message: timedOut ? 'Time expired. Your saved answers were submitted.' : 'Quiz submitted. The public leaderboard will be revealed when the quiz window closes.' });
  } catch (error) { next(error); }
});
app.get('/api/quizzes/:id/leaderboard', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    await sweepExpiredQuizAttempts();
    const quizFilter = req.user.role === 'admin' ? { _id: req.params.id } : { _id: req.params.id, isPublished: true };
    const quiz = await Quiz.findOne(quizFilter); if (!quiz) return sendError(res, 404, 'Quiz not found.');
    if (quizWindow(quiz) !== 'ended') return sendError(res, 409, 'Quiz results will be published when the scheduled quiz period ends.');
    const rows = await quizLeaderboardRows(quiz, { admin: req.user.role === 'admin' });
    res.json({ quiz: { id: String(quiz._id), title: quiz.title, endsAt: quiz.endsAt, resultsFinalizedAt: quiz.resultsFinalizedAt || quiz.endsAt }, leaderboard: rows, rules: 'Ranks are unique. Sort order: score descending, time taken ascending, submission time ascending, then username A–Z. Rank is the final row position plus one.' });
  } catch (error) { next(error); }
});
app.get('/api/admin/quizzes/:quizId/attempts/:attemptId/profile', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.quizId) || !idIsValid(req.params.attemptId)) return sendError(res, 400, 'Invalid quiz or attempt ID.');
    const quiz = await Quiz.findById(req.params.quizId).select('startsAt endsAt isPublished');
    if (!quiz || quizWindow(quiz) !== 'ended' || !quiz.isPublished) return sendError(res, 409, 'Participant contact details are available to admins only from a published, finalized quiz leaderboard.');
    const attempt = await QuizAttempt.findOne({ _id: req.params.attemptId, quizId: req.params.quizId, status: { $in: ['submitted', 'timed_out'] } }).populate({ path: 'userId', select: '+email' }).lean();
    if (!attempt?.userId) return sendError(res, 404, 'Participant profile not found.');
    const u = attempt.userId;
    res.json({ profile: { id: String(u._id), username: u.username, displayName: u.displayName, email: u.email, phoneNumber: u.phoneNumber || '', bio: u.bio || '', avatarUrl: u.avatarUrl || '', interests: u.interests || [], learningGoals: u.learningGoals || [], achievements: u.achievements || [], friendsCount: (u.friends || []).length, role: u.role, emailVerified: Boolean(u.emailVerified), suspended: Boolean(u.suspended), createdAt: u.createdAt, lastActiveAt: u.lastActiveAt, privacy: u.privacy, quickLinks: u.quickLinks || [] }, attempt: { id: String(attempt._id), status: attempt.status, startedAt: attempt.startedAt, submittedAt: attempt.submittedAt, score: attempt.score, totalPoints: attempt.totalPoints, elapsedSeconds: attempt.elapsedSeconds, prizeAwarded: attempt.prizeAwarded, prizeAmount: attempt.prizeAmount, prizeNote: attempt.prizeNote, prizeReceived: attempt.prizeReceived } });
  } catch (error) { next(error); }
});
app.patch('/api/admin/quizzes/:quizId/attempts/:attemptId/prize', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.quizId) || !idIsValid(req.params.attemptId)) return sendError(res, 400, 'Invalid quiz or attempt ID.');
    const quiz = await Quiz.findById(req.params.quizId).select('startsAt endsAt isPublished');
    if (!quiz || quizWindow(quiz) !== 'ended' || !quiz.isPublished) return sendError(res, 409, 'Cash prizes can be marked only from a published quiz leaderboard after the scheduled end time.');
    const attempt = await QuizAttempt.findOne({ _id: req.params.attemptId, quizId: req.params.quizId, status: { $in: ['submitted', 'timed_out'] } });
    if (!attempt) return sendError(res, 404, 'Completed quiz attempt not found.');
    const awarded = req.body.awarded === true; const amount = Number(req.body.amount || 0);
    if (!Number.isFinite(amount) || amount < 0 || amount > 100000000 || (awarded && amount <= 0)) return sendError(res, 400, 'Prize amount must be greater than zero when awarding a cash prize.');
    const nextAmount = awarded ? Math.round(amount * 100) / 100 : 0;
    const nextNote = awarded ? cleanText(req.body.note, 300) : '';
    if (attempt.prizeReceived && (!awarded || nextAmount !== Number(attempt.prizeAmount || 0))) { attempt.prizeReceived = false; attempt.prizeReceivedAt = undefined; }
    attempt.prizeAwarded = awarded; attempt.prizeAmount = nextAmount; attempt.prizeNote = nextNote;
    if (!awarded) { attempt.prizeReceived = false; attempt.prizeReceivedAt = undefined; }
    await attempt.save(); res.json({ ok: true, prizeAwarded: attempt.prizeAwarded, prizeAmount: attempt.prizeAmount, prizeReceived: attempt.prizeReceived });
  } catch (error) { next(error); }
});
app.post('/api/quizzes/:id/prize/confirm', auth, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid quiz ID.');
    const attempt = await QuizAttempt.findOne({ quizId: req.params.id, userId: req.user._id, status: { $in: ['submitted', 'timed_out'] }, prizeAwarded: true, prizeAmount: { $gt: 0 } });
    if (!attempt) return sendError(res, 404, 'There is no cash prize for this account to confirm.');
    attempt.prizeReceived = true; attempt.prizeReceivedAt = new Date(); await attempt.save(); res.json({ ok: true, message: 'Prize receipt confirmed. The confirmed prize now appears publicly on the quiz leaderboard.' });
  } catch (error) { next(error); }
});

app.get('/api/admin/challenges', auth, requireAdmin, async (req, res, next) => {
  try { const challenges = await Challenge.find().sort({ createdAt: -1 }).limit(300).populate('creatorId', 'username displayName'); res.json({ challenges: challenges.map(c => ({ id: String(c._id), title: c.title, description: c.description, type: c.type, goal: c.goal, startsAt: c.startsAt, endsAt: c.endsAt, visibility: c.visibility, creator: c.creatorId ? { username: c.creatorId.username, displayName: c.creatorId.displayName } : null, participantCount: c.participants.length })) }); }
  catch (error) { next(error); }
});
app.patch('/api/admin/challenges/:id', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid challenge ID.');
    const challenge = await Challenge.findById(req.params.id); if (!challenge) return sendError(res, 404, 'Challenge not found.');
    if (req.body.title !== undefined) { const v = cleanText(req.body.title, 100); if (v.length < 3) return sendError(res, 400, 'Challenge title must be at least 3 characters.'); challenge.title = v; }
    if (req.body.description !== undefined) challenge.description = cleanText(req.body.description, 500);
    if (req.body.type !== undefined) { if (!['study_minutes', 'lessons', 'streak'].includes(req.body.type)) return sendError(res, 400, 'Choose a valid challenge type.'); challenge.type = req.body.type; }
    if (req.body.goal !== undefined) { const v = Math.floor(Number(req.body.goal)); if (!Number.isInteger(v) || v < 1 || v > 100000) return sendError(res, 400, 'Challenge goal must be between 1 and 100,000.'); challenge.goal = v; }
    if (req.body.startsAt !== undefined) challenge.startsAt = new Date(req.body.startsAt);
    if (req.body.endsAt !== undefined) challenge.endsAt = new Date(req.body.endsAt);
    if (!Number.isFinite(new Date(challenge.startsAt).getTime()) || !Number.isFinite(new Date(challenge.endsAt).getTime()) || challenge.endsAt <= challenge.startsAt) return sendError(res, 400, 'Challenge end must be after its start.');
    if (req.body.visibility !== undefined) { if (!['public', 'friends'].includes(req.body.visibility)) return sendError(res, 400, 'Choose public or friends visibility.'); challenge.visibility = req.body.visibility; }
    await challenge.save(); res.json({ ok: true, message: 'Challenge updated.' });
  } catch (error) { next(error); }
});
app.patch('/api/admin/users/:id/suspension', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id) || String(req.user._id) === req.params.id) return sendError(res, 400, 'Invalid target user.');
    const suspended = req.body.suspended === true;
    const user = await User.findByIdAndUpdate(req.params.id, { $set: { suspended, suspensionReason: suspended ? cleanText(req.body.reason || 'Community guideline violation', 300) : '' } }, { new: true });
    if (!user) return sendError(res, 404, 'User not found.');
    res.json({ ok: true, suspended: user.suspended, username: user.username });
  } catch (error) { next(error); }
});
app.delete('/api/admin/challenges/:id', auth, requireAdmin, async (req, res, next) => {
  try { if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid challenge ID.'); const result = await Challenge.deleteOne({ _id: req.params.id }); if (!result.deletedCount) return sendError(res, 404, 'Challenge not found.'); res.json({ ok: true }); }
  catch (error) { next(error); }
});
app.delete('/api/admin/messages/:id', auth, requireAdmin, async (req, res, next) => {
  try { if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid message ID.'); const result = await Message.deleteOne({ _id: req.params.id }); if (!result.deletedCount) return sendError(res, 404, 'Message not found.'); res.json({ ok: true }); }
  catch (error) { next(error); }
});

app.get('/api/admin/reports', auth, requireAdmin, async (req, res, next) => {
  try {
    const status = ['open', 'reviewed', 'actioned', 'dismissed'].includes(req.query.status) ? req.query.status : 'open';
    const reports = await Report.find({ status }).sort({ createdAt: -1 }).limit(100).populate('reporterId', 'username displayName');
    res.json({ reports: reports.map(r => ({ id: String(r._id), reporter: r.reporterId ? publicUser(r.reporterId) : null, targetType: r.targetType, targetId: r.targetId, reason: r.reason, details: r.details, status: r.status, createdAt: r.createdAt })) });
  } catch (error) { next(error); }
});
app.patch('/api/admin/reports/:id', auth, requireAdmin, async (req, res, next) => {
  try {
    if (!idIsValid(req.params.id)) return sendError(res, 400, 'Invalid report ID.');
    const status = ['reviewed', 'actioned', 'dismissed'].includes(req.body.status) ? req.body.status : null;
    if (!status) return sendError(res, 400, 'Choose reviewed, actioned, or dismissed.');
    const report = await Report.findByIdAndUpdate(req.params.id, { $set: { status } }, { new: true });
    if (!report) return sendError(res, 404, 'Report not found.'); res.json({ ok: true, status: report.status });
  } catch (error) { next(error); }
});

app.post('/api/reports', auth, async (req, res, next) => {
  try {
    const targetType = ['user', 'message', 'challenge'].includes(req.body.targetType) ? req.body.targetType : null;
    const reason = ['spam', 'harassment', 'inappropriate', 'impersonation', 'other'].includes(req.body.reason) ? req.body.reason : null;
    const targetId = cleanText(req.body.targetId, 100); if (!targetType || !reason || !targetId) return sendError(res, 400, 'Target type, target ID, and a valid report reason are required.');
    const report = await Report.create({ reporterId: req.user._id, targetType, targetId, reason, details: cleanText(req.body.details, 1000) }); res.status(201).json({ ok: true, reportId: String(report._id), message: 'Report submitted for moderator review.' });
  } catch (error) { next(error); }
});

app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'], maxAge: production ? '1h' : 0 }));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/health') return next();
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, _next) => {
  if (err?.message?.startsWith('Origin not allowed')) return res.status(403).json({ error: err.message });
  if (err?.name === 'ValidationError') return res.status(400).json({ error: 'Submitted data did not pass validation.' });
  if (err?.code === 11000) return res.status(409).json({ error: 'That record already exists.' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Request payload is too large.' });
  console.error('Study Lock API error:', err);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});
