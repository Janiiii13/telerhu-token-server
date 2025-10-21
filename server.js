// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { RtcTokenBuilder, RtcRole } = require('agora-access-token');

const APP_ID = process.env.APP_ID;
const APP_CERT = process.env.APP_CERT;
const FIREBASE_DATABASE_URL = process.env.FIREBASE_DATABASE_URL;

// Basic validations for required server envs
if (!APP_ID || !APP_CERT) {
  console.error('Missing Agora APP_ID or APP_CERT in environment. Set APP_ID and APP_CERT.');
  process.exit(1);
}
if (!FIREBASE_DATABASE_URL) {
  console.error('Missing FIREBASE_DATABASE_URL in environment.');
  process.exit(1);
}

// Load Firebase service account: prefer JSON env, fallback to path
const saJsonEnv = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
const saPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH; // optional: path to local JSON file in container
let serviceAccount;

if (saJsonEnv) {
  try {
    // Expecting a valid JSON string (single-line or multi-line). Parse it safely.
    serviceAccount = JSON.parse(saJsonEnv);
  } catch (err) {
    console.error('Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON environment variable. Make sure it contains valid JSON (no "..." placeholders).');
    console.error('Parse error:', err.message);
    process.exit(1);
  }
} else if (saPath) {
  try {
    // require will load and parse the JSON file; safe for local dev if file exists in the container
    serviceAccount = require(saPath);
  } catch (err) {
    console.error(`Failed to load service account from path: ${saPath}`);
    console.error('Error:', err.message);
    process.exit(1);
  }
} else {
  console.error('Missing Firebase service account. Set FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_PATH.');
  process.exit(1);
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: FIREBASE_DATABASE_URL,
  });
} catch (err) {
  console.error('Failed to initialize Firebase Admin SDK. Check service account and FIREBASE_DATABASE_URL.');
  console.error('Error:', err.message);
  process.exit(1);
}

const db = admin.database();

const app = express();
app.use(cors());
app.use(express.json());

// helper to verify Firebase ID token from Authorization: Bearer <idToken>
async function verifyIdTokenFromHeader(req) {
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.split('Bearer ')[1] : null;
  if (!idToken) throw new Error('Missing ID token in Authorization header');
  const decoded = await admin.auth().verifyIdToken(idToken);
  return decoded; // contains uid, claims, etc.
}

function buildAgoraToken(channel, agoraUid = 0, agoraRole = RtcRole.PUBLISHER, expireSeconds = 3600) {
  const ts = Math.floor(Date.now() / 1000) + expireSeconds;
  return RtcTokenBuilder.buildTokenWithUid(APP_ID, APP_CERT, channel, agoraUid, agoraRole, ts);
}

/* POST /call/initiate
   Body: { doctorUid: "<doctor uid>" }
   Header: Authorization: Bearer <Firebase ID token>
*/
app.post('/call/initiate', async (req, res) => {
  try {
    const decoded = await verifyIdTokenFromHeader(req);
    const callerUid = decoded.uid;
    const { doctorUid } = req.body;
    if (!doctorUid) return res.status(400).json({ error: 'doctorUid required' });

    const channel = `room-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    const ref = db.ref('calls').push();
    const roomId = ref.key;

    const callObj = {
      channel,
      callerUid,
      doctorUid,
      status: 'ringing',
      createdAt: admin.database.ServerValue.TIMESTAMP
    };

    await ref.set(callObj);

    // Add incoming pointer for doctor
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).set({
      roomId,
      channel,
      callerUid,
      createdAt: admin.database.ServerValue.TIMESTAMP
    });

    // Issue caller token and save it
    const callerToken = buildAgoraToken(channel, 0, RtcRole.PUBLISHER);
    await ref.child('callerToken').set(callerToken);

    return res.json({ roomId, channel, token: callerToken });
  } catch (err) {
    console.error('Initiate call error:', err.message || err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

/* POST /call/accept
   Body: { roomId: "<room id>" }
   Header: Authorization: Bearer <Firebase ID token>
*/
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

    await callRef.update({
      status: 'accepted',
      doctorResponseAt: admin.database.ServerValue.TIMESTAMP
    });

    // remove the doctor's incomingCalls pointer
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    // issue doctor token and save it
    const doctorToken = buildAgoraToken(call.channel, 0, RtcRole.PUBLISHER);
    await callRef.child('doctorToken').set(doctorToken);

    // make sure status is set (redundant with update above but explicit)
    await callRef.child('status').set('accepted');

    return res.json({ token: doctorToken, channel: call.channel });
  } catch (err) {
    console.error('Accept call error:', err.message || err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

/* POST /call/reject
   Body: { roomId: "<room id>" }
   Header: Authorization: Bearer <Firebase ID token>
*/
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

    await callRef.update({
      status: 'rejected',
      doctorResponseAt: admin.database.ServerValue.TIMESTAMP
    });

    // cleanup doctor's incoming pointer
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    return res.json({ ok: true });
  } catch (err) {
    console.error('Reject call error:', err.message || err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

// Health check endpoint (useful for quick smoke tests)
app.get('/', (req, res) => res.send('Agora token server OK'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
