const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// ─── SIMPLE JSON FILE DATABASE (works everywhere, no native modules) ──────────
const DB_FILE = path.join(__dirname, 'db.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: {}, groups: {}, memberships: [], contributions: [], withdrawal_requests: [], votes: [], notifications: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'stokvela-za-2025-secure';

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function now() { return new Date().toISOString(); }

function addNotif(db, userId, type, title, message, groupId = null) {
  db.notifications.push({ id: uuidv4(), user_id: userId, group_id: groupId, type, title, message, read: false, created_at: now() });
}

function blastGroup(db, groupId, type, title, message, excludeId = null) {
  const members = db.memberships.filter(m => m.group_id === groupId);
  for (const m of members) {
    if (m.user_id !== excludeId) addNotif(db, m.user_id, type, title, message, groupId);
  }
}

function currentMonth() { return new Date().toISOString().substring(0, 7); }

// ─── AUTH ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, phone, pin, email } = req.body;
  if (!name || !phone || !pin) return res.status(400).json({ error: 'Name, phone and PIN required' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });

  const db = loadDB();
  if (Object.values(db.users).find(u => u.phone === phone))
    return res.status(409).json({ error: 'Phone number already registered' });

  const id = uuidv4();
  const pin_hash = await bcrypt.hash(pin, 10);
  db.users[id] = { id, name, phone, email: email || null, pin_hash, bank_name: null, bank_account: null, bank_branch: null, created_at: now() };
  addNotif(db, id, 'welcome', 'Welcome to Stokvela! 🎉', `Sharp sharp ${name}! Your account is ready. Create or join a stokvel group to get started.`);
  saveDB(db);

  const token = jwt.sign({ id, name, phone }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, name, phone, email: email || null } });
});

app.post('/api/auth/login', async (req, res) => {
  const { phone, pin } = req.body;
  if (!phone || !pin) return res.status(400).json({ error: 'Phone and PIN required' });

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.phone === phone);
  if (!user) return res.status(401).json({ error: 'Phone number not found' });

  const valid = await bcrypt.compare(pin, user.pin_hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect PIN. Try again.' });

  const token = jwt.sign({ id: user.id, name: user.name, phone: user.phone }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, phone: user.phone, email: user.email, bank_name: user.bank_name } });
});

// ─── USER ─────────────────────────────────────────────────────────────────────
app.get('/api/me', auth, (req, res) => {
  const db = loadDB();
  const { pin_hash, ...user } = db.users[req.user.id] || {};
  if (!user.id) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.put('/api/me/bank', auth, (req, res) => {
  const { bank_name, bank_account, bank_branch } = req.body;
  const db = loadDB();
  Object.assign(db.users[req.user.id], { bank_name, bank_account, bank_branch });
  saveDB(db);
  res.json({ success: true });
});

// ─── GROUPS ───────────────────────────────────────────────────────────────────
app.post('/api/groups', auth, (req, res) => {
  const { name, description, monthly_amount, payout_day, max_members } = req.body;
  if (!name || !monthly_amount) return res.status(400).json({ error: 'Name and monthly amount required' });

  const db = loadDB();
  const id = uuidv4();
  const invite_code = Math.random().toString(36).substring(2, 8).toUpperCase();
  db.groups[id] = { id, name, description: description || '', monthly_amount: Number(monthly_amount), payout_day: payout_day || 25, admin_id: req.user.id, invite_code, max_members: max_members || 20, created_at: now() };
  db.memberships.push({ id: uuidv4(), user_id: req.user.id, group_id: id, role: 'admin', payout_order: 1, joined_at: now() });
  addNotif(db, req.user.id, 'group_created', `"${name}" is live! 🏦`, `Invite members with code: ${invite_code}. Monthly contribution: R${monthly_amount}`, id);
  saveDB(db);
  res.json({ id, name, invite_code, monthly_amount });
});

app.get('/api/groups', auth, (req, res) => {
  const db = loadDB();
  const myMemberships = db.memberships.filter(m => m.user_id === req.user.id);
  const groups = myMemberships.map(m => {
    const g = db.groups[m.group_id];
    if (!g) return null;
    const member_count = db.memberships.filter(x => x.group_id === g.id).length;
    const pot_balance = db.contributions.filter(c => c.group_id === g.id && c.status === 'paid').reduce((s, c) => s + c.amount, 0);
    const month_paid = db.contributions.filter(c => c.group_id === g.id && c.month === currentMonth() && c.status === 'paid').length;
    return { ...g, role: m.role, payout_order: m.payout_order, member_count, pot_balance, month_paid };
  }).filter(Boolean);
  res.json(groups);
});

app.get('/api/groups/:id', auth, (req, res) => {
  const db = loadDB();
  const membership = db.memberships.find(m => m.group_id === req.params.id && m.user_id === req.user.id);
  if (!membership) return res.status(403).json({ error: 'You are not a member of this group' });

  const g = db.groups[req.params.id];
  if (!g) return res.status(404).json({ error: 'Group not found' });

  const member_count = db.memberships.filter(m => m.group_id === g.id).length;
  const pot_balance = db.contributions.filter(c => c.group_id === g.id && c.status === 'paid').reduce((s, c) => s + c.amount, 0);

  const members = db.memberships.filter(m => m.group_id === g.id).sort((a, b) => a.payout_order - b.payout_order).map(m => {
    const u = db.users[m.user_id];
    const month_contribution = db.contributions.find(c => c.user_id === m.user_id && c.group_id === g.id && c.month === currentMonth() && c.status === 'paid');
    return { id: u.id, name: u.name, phone: u.phone, bank_name: u.bank_name, role: m.role, payout_order: m.payout_order, joined_at: m.joined_at, paid_this_month: !!month_contribution };
  });

  const contributions = db.contributions.filter(c => c.group_id === g.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 30).map(c => ({ ...c, user_name: db.users[c.user_id]?.name }));

  res.json({ ...g, member_count, pot_balance, members, contributions, my_role: membership.role, my_payout_order: membership.payout_order });
});

app.post('/api/groups/join', auth, (req, res) => {
  const { invite_code } = req.body;
  const db = loadDB();
  const group = Object.values(db.groups).find(g => g.invite_code === invite_code?.toUpperCase().trim());
  if (!group) return res.status(404).json({ error: 'Invalid invite code. Check with your group admin.' });

  if (db.memberships.find(m => m.user_id === req.user.id && m.group_id === group.id))
    return res.status(409).json({ error: 'You are already a member of this group' });

  const count = db.memberships.filter(m => m.group_id === group.id).length;
  if (count >= group.max_members) return res.status(400).json({ error: 'Group is full' });

  db.memberships.push({ id: uuidv4(), user_id: req.user.id, group_id: group.id, role: 'member', payout_order: count + 1, joined_at: now() });
  blastGroup(db, group.id, 'member_joined', `${req.user.name} joined! 👋`, `Welcome ${req.user.name} to the group!`, req.user.id);
  addNotif(db, req.user.id, 'joined', `Joined "${group.name}"! 🎉`, `Monthly: R${group.monthly_amount}. Invite code: ${group.invite_code}`, group.id);
  saveDB(db);
  res.json({ success: true, group });
});

// ─── CONTRIBUTIONS ────────────────────────────────────────────────────────────
app.post('/api/contributions', auth, (req, res) => {
  const { group_id, amount, payment_ref } = req.body;
  const db = loadDB();

  if (!db.memberships.find(m => m.group_id === group_id && m.user_id === req.user.id))
    return res.status(403).json({ error: 'Not a member of this group' });

  const month = currentMonth();
  if (db.contributions.find(c => c.user_id === req.user.id && c.group_id === group_id && c.month === month && c.status === 'paid'))
    return res.status(409).json({ error: `Already contributed for ${month}` });

  const group = db.groups[group_id];
  const contrib = { id: uuidv4(), user_id: req.user.id, group_id, amount: Number(amount), month, status: 'paid', payment_ref: payment_ref || null, paid_at: now(), created_at: now() };
  db.contributions.push(contrib);
  blastGroup(db, group_id, 'contribution', `R${amount} contribution! 💰`, `${req.user.name} paid R${amount} for ${month}.`);
  saveDB(db);
  res.json({ id: contrib.id, success: true });
});

// ─── WITHDRAWALS ──────────────────────────────────────────────────────────────
app.post('/api/withdrawals', auth, (req, res) => {
  const { group_id, amount, reason } = req.body;
  if (!group_id || !amount || !reason) return res.status(400).json({ error: 'group_id, amount and reason are all required' });

  const db = loadDB();
  if (!db.memberships.find(m => m.group_id === group_id && m.user_id === req.user.id))
    return res.status(403).json({ error: 'Not a member' });

  if (db.withdrawal_requests.find(r => r.user_id === req.user.id && r.group_id === group_id && r.status === 'pending'))
    return res.status(409).json({ error: 'You already have a pending withdrawal request' });

  const votes_needed = db.memberships.filter(m => m.group_id === group_id).length;
  const id = uuidv4();
  db.withdrawal_requests.push({ id, user_id: req.user.id, group_id, amount: Number(amount), reason, status: 'pending', votes_yes: 0, votes_no: 0, votes_needed, created_at: now(), resolved_at: null });
  blastGroup(db, group_id, 'withdrawal_signal', `🚨 ${req.user.name} needs R${amount}`, `"${reason}" — All ${votes_needed} members must approve. Check Izigcino.`, req.user.id);
  saveDB(db);
  res.json({ id, success: true, votes_needed });
});

app.get('/api/groups/:id/withdrawals', auth, (req, res) => {
  const db = loadDB();
  if (!db.memberships.find(m => m.group_id === req.params.id && m.user_id === req.user.id))
    return res.status(403).json({ error: 'Not a member' });

  const requests = db.withdrawal_requests.filter(r => r.group_id === req.params.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).map(r => {
    const votes = db.votes.filter(v => v.request_id === r.id).map(v => ({ vote: v.vote, voter_name: db.users[v.voter_id]?.name }));
    const my_vote = db.votes.find(v => v.request_id === r.id && v.voter_id === req.user.id)?.vote || null;
    return { ...r, requester_name: db.users[r.user_id]?.name, votes, my_vote };
  });
  res.json(requests);
});

app.post('/api/withdrawals/:id/vote', auth, (req, res) => {
  const { vote } = req.body;
  if (!['yes', 'no'].includes(vote)) return res.status(400).json({ error: 'Vote must be "yes" or "no"' });

  const db = loadDB();
  const request = db.withdrawal_requests.find(r => r.id === req.params.id);
  if (!request) return res.status(404).json({ error: 'Withdrawal request not found' });
  if (request.status !== 'pending') return res.status(400).json({ error: 'This vote is already closed' });

  if (!db.memberships.find(m => m.group_id === request.group_id && m.user_id === req.user.id))
    return res.status(403).json({ error: 'Not a member of this group' });

  if (db.votes.find(v => v.request_id === req.params.id && v.voter_id === req.user.id))
    return res.status(409).json({ error: 'You have already voted on this request' });

  db.votes.push({ id: uuidv4(), request_id: req.params.id, voter_id: req.user.id, vote, voted_at: now() });

  if (vote === 'yes') {
    request.votes_yes += 1;
    if (request.votes_yes >= request.votes_needed) {
      request.status = 'approved'; request.resolved_at = now();
      const requester = db.users[request.user_id];
      blastGroup(db, request.group_id, 'approved', `✅ Withdrawal approved!`, `${requester.name}'s R${request.amount} withdrawal was unanimously approved!`);
      addNotif(db, request.user_id, 'approved', `🎉 R${request.amount} withdrawal approved!`, `All members said yes! Funds will transfer to your linked bank account.`, request.group_id);
    }
  } else {
    request.votes_no += 1; request.status = 'declined'; request.resolved_at = now();
    const requester = db.users[request.user_id];
    blastGroup(db, request.group_id, 'declined', `Withdrawal declined`, `${req.user.name} declined ${requester?.name}'s R${request.amount} request.`);
    addNotif(db, request.user_id, 'declined', `Withdrawal not approved`, `${req.user.name} declined your R${request.amount} request. You may reapply next month.`, request.group_id);
  }

  saveDB(db);
  res.json({ success: true, vote, status: request.status });
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────
app.get('/api/notifications', auth, (req, res) => {
  const db = loadDB();
  const notifs = db.notifications.filter(n => n.user_id === req.user.id).sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 50);
  const unread_count = notifs.filter(n => !n.read).length;
  res.json({ notifications: notifs, unread_count });
});

app.put('/api/notifications/read-all', auth, (req, res) => {
  const db = loadDB();
  db.notifications.forEach(n => { if (n.user_id === req.user.id) n.read = true; });
  saveDB(db);
  res.json({ success: true });
});

// ─── GROUP BLAST ──────────────────────────────────────────────────────────────
app.post('/api/groups/:id/blast', auth, (req, res) => {
  const { title, message } = req.body;
  const db = loadDB();
  const membership = db.memberships.find(m => m.group_id === req.params.id && m.user_id === req.user.id);
  if (!membership || membership.role !== 'admin') return res.status(403).json({ error: 'Only the group admin can send blasts' });
  blastGroup(db, req.params.id, 'blast', title, message);
  saveDB(db);
  res.json({ success: true });
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', app: 'Stokvela', time: now() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🏦 Stokvela backend running on http://localhost:${PORT}`));
 
