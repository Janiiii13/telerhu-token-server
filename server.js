// server.js (updated)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { RtcTokenBuilder, RtcRole } = require('agora-access-token');

const APP_ID = process.env.APP_ID || '957be99365fe4ee49f52891b99991cbd';
const APP_CERT = process.env.APP_CERT || 'db9d9e31a5e74f3884f2425ed4b62dda';

if (!APP_ID || !APP_CERT) {
  console.error('Missing APP_ID or APP_CERT. Set APP_ID and APP_CERT in environment.');
  process.exit(1);
}

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error('FIREBASE_SERVICE_ACCOUNT_JSON missing in env');
  process.exit(1);
}

let serviceAccount;
try {
  // parse the full JSON string provided in env var
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} catch (err) {
  console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON. Ensure it is valid JSON string.', err.message);
  process.exit(1);
}

if (!process.env.FIREBASE_DATABASE_URL) {
  console.error('FIREBASE_DATABASE_URL missing in env');
  process.exit(1);
}

// ------------------ NEW: normalize private_key to valid PEM ------------------
try {
  if (!serviceAccount || typeof serviceAccount.private_key !== 'string') {
    throw new Error('private_key missing or not a string in service account JSON');
  }

  let pk = serviceAccount.private_key;

  // 1) if the string contains double-escaped backslash-n (\\n) turn them into \n first
  //    this handles cases where dotenv or other tooling double-escaped.
  pk = pk.replace(/\\\\n/g, '\\n');

  // 2) convert any escaped \n into real newlines
  pk = pk.replace(/\\n/g, '\n');

  // 3) defensive trim and remove surrounding quotes (if any)
  pk = pk.trim().replace(/^"+|"+$/g, '');

  // 4) ensure header/footer exist (add if missing)
  if (!pk.startsWith('-----BEGIN PRIVATE KEY-----')) {
    pk = '-----BEGIN PRIVATE KEY-----\n' + pk;
  }
  if (!pk.trim().endsWith('-----END PRIVATE KEY-----')) {
    pk = pk + '\n-----END PRIVATE KEY-----';
  }

  // 5) ensure it ends with a newline
  pk = pk.trim() + '\n';

  // assign back
  serviceAccount.private_key = pk;

  // quick sanity checks (do NOT print the key itself)
  const okHeader = serviceAccount.private_key.startsWith('-----BEGIN PRIVATE KEY-----');
  const okFooter = serviceAccount.private_key.trim().endsWith('-----END PRIVATE KEY-----');
  if (!okHeader || !okFooter) {
    console.error('Private key header/footer check failed after normalization.');
    console.error('private_key length:', serviceAccount.private_key.length);
    throw new Error('Invalid PEM formatted private key after normalization.');
  }
} catch (err) {
  console.error('Failed to normalize/validate private_key:', err.message);
  process.exit(1);
}
// ---------------------------------------------------------------------------

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
  console.log('Firebase Admin initialized.');
} catch (err) {
  console.error('Failed to initialize Firebase Admin SDK:', err && err.message ? err.message : err);
  process.exit(1);
}

const db = admin.database();

const app = express();
app.use(cors());
app.use(express.json());

// simple root and health endpoints
app.get('/', (req, res) => {
  res.send('✅ Server running. Use /call/initiate, /call/accept, /call/reject endpoints.');
});

app.get('/health', (req, res) => {
  res.json({ ok: true, time: Date.now(), env: process.env.NODE_ENV || 'unknown' });
});

// Improved verifier with logging of Firebase auth error codes
async function verifyIdTokenFromHeader(req) {
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.split('Bearer ')[1] : null;
  if (!idToken) {
    const e = new Error('Missing ID token');
    e.code = 'NO_ID_TOKEN';
    throw e;
  }
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    console.log('verifyIdToken OK uid=', decoded.uid);
    return decoded;
  } catch (err) {
    // log error code and message for debugging (e.g. expired, revoked, admin-restricted)
    console.error('verifyIdToken failed. code=', err.code, 'message=', err.message);
    throw err;
  }
}

function buildAgoraToken(channel, agoraUid = 0, agoraRole = RtcRole.PUBLISHER, expireSeconds = 3600) {
  const ts = Math.floor(Date.now() / 1000) + expireSeconds;
  return RtcTokenBuilder.buildTokenWithUid(APP_ID, APP_CERT, channel, agoraUid, agoraRole, ts);
}

app.post('/call/initiate', async (req, res) => {
  try {
    const decoded = await verifyIdTokenFromHeader(req);
    const callerUid = decoded.uid;
    const { doctorUid } = req.body;
    if (!doctorUid) return res.status(400).json({ error: 'doctorUid required' });

    // ensure doctorUid exists and has role 'doctor' (if your DB uses different field change accordingly)
    const userSnap = await db.ref(`users/${doctorUid}`).once('value');
    const userData = userSnap.val();
    if (!userData || (String(userData.role || '').toLowerCase() !== 'doctor')) {
      return res.status(403).json({ error: 'Target user is not a doctor' });
    }

    const channel = `room-${Date.now()}-${Math.floor(Math.random()*1000)}`;
    const roomRef = db.ref('calls').push();
    const roomId = roomRef.key;

    const callObj = {
      channel,
      callerUid,
      doctorUid,
      status: 'ringing',
      createdAt: admin.database.ServerValue.TIMESTAMP,
    };

    await roomRef.set(callObj);

    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).set({
      roomId,
      channel,
      callerUid,
      createdAt: admin.database.ServerValue.TIMESTAMP
    });

    const callerToken = buildAgoraToken(channel, 0, RtcRole.PUBLISHER);
    await db.ref(`calls/${roomId}/callerToken`).set(callerToken);

    return res.json({ roomId, channel, token: callerToken });
  } catch (err) {
    console.error('/call/initiate error:', err && err.code ? `${err.code} ${err.message}` : err);
    if (err && err.code === 'NO_ID_TOKEN') return res.status(400).json({ error: err.message });
    // If verification error from Firebase Auth propagate its message but respond 401
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

app.post('/call/accept', async (req, res) => {
  try {
    const decoded = await verifyIdTokenFromHeader(req);
    const doctorUid = decoded.uid;
    const { roomId } = req.body;
    if (!roomId) return res.status(400).json({ error: 'roomId required' });

    const callRef = db.ref(`calls/${roomId}`);
    const snap = await callRef.once('value');
    const call = snap.val();
    if (!call) return res.status(404).json({ error: 'call not found' });
    if (call.doctorUid !== doctorUid) return res.status(403).json({ error: 'not the invited doctor' });

    await callRef.update({ status: 'accepted', doctorResponseAt: admin.database.ServerValue.TIMESTAMP });

    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    const doctorToken = buildAgoraToken(call.channel, 0, RtcRole.PUBLISHER);
    await callRef.child('doctorToken').set(doctorToken);

    // ensure status visible
    await callRef.child('status').set('accepted');

    return res.json({ token: doctorToken, channel: call.channel });
  } catch (err) {
    console.error('/call/accept error:', err && err.code ? `${err.code} ${err.message}` : err);
    if (err && err.code === 'NO_ID_TOKEN') return res.status(400).json({ error: err.message });
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

app.post('/call/reject', async (req, res) => {
  try {
    const decoded = await verifyIdTokenFromHeader(req);
    const doctorUid = decoded.uid;
    const { roomId } = req.body;
    if (!roomId) return res.status(400).json({ error: 'roomId required' });

    const callRef = db.ref(`calls/${roomId}`);
    const snap = await callRef.once('value');
    const call = snap.val();
    if (!call) return res.status(404).json({ error: 'call not found' });
    if (call.doctorUid !== doctorUid) return res.status(403).json({ error: 'not the invited doctor' });

    await callRef.update({ status: 'rejected', doctorResponseAt: admin.database.ServerValue.TIMESTAMP });

    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    return res.json({ ok: true });
  } catch (err) {
    console.error('/call/reject error:', err && err.code ? `${err.code} ${err.message}` : err);
    if (err && err.code === 'NO_ID_TOKEN') return res.status(400).json({ error: err.message });
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
