// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { RtcTokenBuilder, RtcRole } = require('agora-access-token');

const APP_ID = process.env.APP_ID;
const APP_CERT = process.env.APP_CERT;

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.error('FIREBASE_SERVICE_ACCOUNT_JSON missing in env');
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),
  databaseURL: process.env.FIREBASE_DATABASE_URL // set this in .env, e.g. https://<proj>.firebaseio.com
});

const db = admin.database();

const app = express();
app.use(cors());
app.use(express.json());

// helper to verify Firebase ID token from Authorization: Bearer <idToken>
async function verifyIdTokenFromHeader(req) {
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.split('Bearer ')[1] : null;
  if (!idToken) throw new Error('Missing ID token');
  const decoded = await admin.auth().verifyIdToken(idToken);
  return decoded; // contains uid, claims, etc.
}

function buildAgoraToken(channel, agoraUid = 0, agoraRole = RtcRole.PUBLISHER, expireSeconds = 3600) {
  const ts = Math.floor(Date.now() / 1000) + expireSeconds;
  return RtcTokenBuilder.buildTokenWithUid(APP_ID, APP_CERT, channel, agoraUid, agoraRole, ts);
}

// 1) User initiates call
app.post('/call/initiate', async (req, res) => {
  try {
    const decoded = await verifyIdTokenFromHeader(req);
    const callerUid = decoded.uid;
    const { doctorUid } = req.body;
    if (!doctorUid) return res.status(400).json({ error: 'doctorUid required' });

    // create channel / roomId
    const channel = `room-${Date.now()}-${Math.floor(Math.random()*1000)}`;
    const roomId = db.ref('calls').push().key;

    const callObj = {
      channel,
      callerUid,
      doctorUid,
      status: 'ringing',
      createdAt: admin.database.ServerValue.TIMESTAMP,
      // Optionally pre-issue caller token:
      // callerToken: buildAgoraToken(channel, 0, RtcRole.PUBLISHER)
    };

    await db.ref(`calls/${roomId}`).set(callObj);

    // You can push a lightweight notification field for quick UX:
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).set({
      roomId,
      channel,
      callerUid,
      createdAt: admin.database.ServerValue.TIMESTAMP
    });

    // Issue and return a token for caller so caller can publish while waiting
    const callerToken = buildAgoraToken(channel, 0, RtcRole.PUBLISHER);
    await db.ref(`calls/${roomId}/callerToken`).set(callerToken);

    return res.json({ roomId, channel, token: callerToken });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

// 2) Doctor accepts
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

    // mark accepted
    await callRef.update({
      status: 'accepted',
      doctorResponseAt: admin.database.ServerValue.TIMESTAMP
    });

    // remove the incomingCalls notification reference
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    // issue doctor token (broadcaster)
    const doctorToken = buildAgoraToken(call.channel, 0, RtcRole.PUBLISHER);
    await callRef.child('doctorToken').set(doctorToken);

    // notify caller by writing a small field; caller listens for status change
    await callRef.child('status').set('accepted');

    return res.json({ token: doctorToken, channel: call.channel });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

// 3) Doctor rejects
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

    // cleanup doctor incomingCalls notification
    await db.ref(`users/${doctorUid}/incomingCalls/${roomId}`).remove();

    // optionally cleanup the call after notifying caller
    // await callRef.remove();

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: err.message || 'auth failed' });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
