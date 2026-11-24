'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');
const { Firestore } = require('@google-cloud/firestore');
const crypto = require('node:crypto');

const required = [
  'JWT_SECRET',
  'TEACHER_PASSWORD_HASH',
  'ADMIN_SETUP_CODE',
  'FIREBASE_SERVICE_ACCOUNT'
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters.');
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} catch {
  throw new Error('FIREBASE_SERVICE_ACCOUNT must contain valid JSON.');
}

const db = new Firestore({
  projectId: serviceAccount.project_id,
  credentials: {
    client_email: serviceAccount.client_email,
    private_key: serviceAccount.private_key
  }
});

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  crossOriginResourcePolicy: {
    policy: 'cross-origin'
  }
}));

const origins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

console.log('Allowed origins:', origins);

app.use(cors({
  origin(origin, cb) {
    console.log('Browser origin received:', origin);

    if (!origin && process.env.NODE_ENV !== 'production') {
      return cb(null, true);
    }

    if (origins.length > 0 && origins.includes(origin)) {
      return cb(null, true);
    }

    return cb(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Device-Signature'
  ]
}));

app.use(express.json({
  limit: '256kb'
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts. Try again in 15 minutes.'
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.use('/api', apiLimiter);

const sysRef = db.collection('system').doc('security');
const challenges = new Map();
const MAX_CHALLENGES = 1000;

const today = () => new Date().toLocaleDateString('en-CA', {
  timeZone: 'Asia/Kolkata'
});

const clean = (v, max = 100) =>
  typeof v === 'string'
    ? v.trim().replace(/[<>\u0000-\u001f]/g, '').slice(0, max)
    : '';

const validDate = s =>
  /^\d{4}-\d{2}-\d{2}$/.test(s) &&
  s >= (() => {
    const d = new Date();
    d.setDate(d.getDate() - 29);
    return d.toLocaleDateString('en-CA', {
      timeZone: 'Asia/Kolkata'
    });
  })() &&
  s <= today();

function tokenFor(role, name) {
  return jwt.sign(
    { role, name },
    process.env.JWT_SECRET,
    {
      expiresIn: role === 'admin' ? '2h' : '8h',
      issuer: 'ccc-attendance'
    }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';

  try {
    if (!h.startsWith('Bearer ')) {
      throw new Error('missing');
    }

    req.session = jwt.verify(
      h.slice(7),
      process.env.JWT_SECRET,
      { issuer: 'ccc-attendance' }
    );

    next();
  } catch {
    res.status(401).json({
      error: 'Please sign in again.'
    });
  }
}

const adminOnly = (req, res, next) =>
  req.session?.role === 'admin'
    ? next()
    : res.status(403).json({
        error: 'Admin permission required.'
      });

async function verifySharedPassword(password) {
  if (
    typeof password !== 'string' ||
    password.length < 8 ||
    password.length > 128
  ) {
    return false;
  }

  return bcrypt.compare(
    password,
    process.env.TEACHER_PASSWORD_HASH
  );
}

app.get('/', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'CCC Students Attendance secure API',
    version: '1.0.0'
  });
});

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

// Teacher login
app.post('/api/auth/teacher', loginLimiter, async (req, res) => {
  const name = clean(req.body?.name, 60);
  const password = req.body?.password;

  if (!name || !await verifySharedPassword(password)) {
    return res.status(401).json({
      error: 'Name or password is incorrect.'
    });
  }

  res.json({
    token: tokenFor('teacher', name),
    role: 'teacher',
    name,
    expiresIn: 28800
  });
});

// Admin login challenge
app.post('/api/auth/challenge', loginLimiter, async (_req, res) => {
  const challenge = crypto.randomBytes(32).toString('base64url');
  const id = crypto.randomBytes(18).toString('base64url');

  if (challenges.size >= MAX_CHALLENGES) {
    challenges.delete(challenges.keys().next().value);
  }

  challenges.set(id, {
    challenge,
    expires: Date.now() + 120000
  });

  res.json({
    challengeId: id,
    challenge
  });
});

// Backward compatibility with the previously enrolled single device
function adminDeviceList(data) {
  if (Array.isArray(data?.adminDevices)) {
    return data.adminDevices;
  }

  if (data?.adminDevice?.publicJwk) {
    return [{
      id: 'legacy',
      publicJwk: data.adminDevice.publicJwk,
      deviceName: 'Previously enrolled device',
      enrolledAt: data.adminDevice.enrolledAt || null,
      enrolledBy: data.adminDevice.enrolledBy || null
    }];
  }

  return [];
}

function validPublicJwk(jwk) {
  if (
    !jwk ||
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    !jwk.x ||
    !jwk.y ||
    jwk.d
  ) {
    return false;
  }

  try {
    crypto.createPublicKey({
      key: jwk,
      format: 'jwk'
    });

    return true;
  } catch {
    return false;
  }
}

function hashInvite(code) {
  return crypto
    .createHash('sha256')
    .update(code)
    .digest('hex');
}

// Admin login with registered device verification
app.post('/api/auth/admin', loginLimiter, async (req, res) => {
  const name = clean(req.body?.name, 60);
  const password = req.body?.password;

  const {
    challengeId,
    signature
  } = req.body || {};

  const deviceId = clean(req.body?.deviceId, 80) || 'legacy';

  if (!name || !await verifySharedPassword(password)) {
    return res.status(401).json({
      error: 'Name or password is incorrect.'
    });
  }

  const c = challenges.get(challengeId);
  challenges.delete(challengeId);

  if (
    !c ||
    c.expires < Date.now() ||
    typeof signature !== 'string'
  ) {
    return res.status(401).json({
      error: 'Device verification expired. Try again.'
    });
  }

  const snap = await sysRef.get();
  const data = snap.exists ? snap.data() : {};

  const device = adminDeviceList(data)
    .find(d => d.id === deviceId);

  if (!device?.publicJwk) {
    return res.status(403).json({
      error: 'This device is not registered. Generate an invitation from an approved Admin device.'
    });
  }

  try {
    const pub = crypto.createPublicKey({
      key: device.publicJwk,
      format: 'jwk'
    });

    const ok = crypto.verify(
      'sha256',
      Buffer.from(c.challenge),
      {
        key: pub,
        dsaEncoding: 'ieee-p1363'
      },
      Buffer.from(signature, 'base64url')
    );

    if (!ok) {
      return res.status(403).json({
        error: 'This is not the approved admin device.'
      });
    }
  } catch {
    return res.status(400).json({
      error: 'Invalid device proof.'
    });
  }

  res.json({
    token: tokenFor('admin', name),
    role: 'admin',
    name,
    expiresIn: 7200
  });
});

// Register first device or an invited additional device
app.post('/api/admin/enroll-device', loginLimiter, async (req, res) => {
  const name = clean(req.body?.name, 60);
  const password = req.body?.password;

  const setupCode = req.body?.setupCode;
  const inviteCode = req.body?.inviteCode;
  const publicJwk = req.body?.publicJwk;
  const deviceId = clean(req.body?.deviceId, 80);
  const deviceName = clean(req.body?.deviceName, 60) || 'Admin device';

  if (!name || !await verifySharedPassword(password)) {
    return res.status(401).json({
      error: 'Name or password is incorrect.'
    });
  }

  if (!deviceId || !validPublicJwk(publicJwk)) {
    return res.status(400).json({
      error: 'A valid device ID and public P-256 key are required.'
    });
  }

  // Additional devices must use an invitation code
  if (
    typeof inviteCode === 'string' &&
    inviteCode.length >= 20 &&
    inviteCode.length <= 256 &&
    inviteCode !== process.env.ADMIN_SETUP_CODE
  ) {
    const wantedHash = hashInvite(inviteCode);
    let outcome = 'ok';

    await db.runTransaction(async tx => {
      const snap = await tx.get(sysRef);
      const data = snap.exists ? snap.data() : {};

      const devices = adminDeviceList(data);

      if (devices.length >= 3) {
        outcome = 'limit';
        return;
      }

      const invites = Array.isArray(data.adminInvites)
        ? data.adminInvites
        : [];

      const index = invites.findIndex(i =>
        i.hash === wantedHash &&
        Number(i.expiresAt) > Date.now()
      );

      if (index < 0) {
        outcome = 'invite';
        return;
      }

      if (devices.some(d => d.id === deviceId)) {
        outcome = 'duplicate';
        return;
      }

      const nextInvites = invites.filter((_, i) => i !== index);

      const nextDevices = [
        ...devices,
        {
          id: deviceId,
          publicJwk,
          deviceName,
          enrolledAt: new Date().toISOString(),
          enrolledBy: name
        }
      ];

      tx.set(sysRef, {
        adminDevices: nextDevices,
        adminInvites: nextInvites,
        securityVersion: 2
      }, { merge: true });
    });

    if (outcome === 'limit') {
      return res.status(409).json({
        error: 'The maximum of 3 admin devices is already registered.'
      });
    }

    if (outcome === 'invite') {
      return res.status(403).json({
        error: 'Invitation code is invalid or expired. Generate a new one on an approved device.'
      });
    }

    if (outcome === 'duplicate') {
      return res.status(409).json({
        error: 'This device is already registered.'
      });
    }

    return res.status(201).json({
      ok: true,
      message: 'Admin device registered.',
      deviceId
    });
  }

  // Initial device setup using the one-time setup code
  const initialCode =
    typeof setupCode === 'string'
      ? setupCode
      : inviteCode;

  if (
    typeof initialCode !== 'string' ||
    initialCode.length < 20 ||
    initialCode.length > 256 ||
    initialCode.length !== process.env.ADMIN_SETUP_CODE.length ||
    !crypto.timingSafeEqual(
      Buffer.from(initialCode),
      Buffer.from(process.env.ADMIN_SETUP_CODE)
    )
  ) {
    return res.status(403).json({
      error: 'A valid invitation code is required for initial setup.'
    });
  }

  let outcome = 'ok';

  await db.runTransaction(async tx => {
    const snap = await tx.get(sysRef);
    const data = snap.exists ? snap.data() : {};

    if (adminDeviceList(data).length || data.setupCodeUsed) {
      outcome = 'already';
      return;
    }

    tx.set(sysRef, {
      adminDevices: [{
        id: deviceId,
        publicJwk,
        deviceName,
        enrolledAt: new Date().toISOString(),
        enrolledBy: name
      }],
      setupCodeUsed: true,
      securityVersion: 2
    }, { merge: true });
  });

  if (outcome === 'already') {
    return res.status(409).json({
      error: 'Initial admin device is already registered. Use an invitation from that device.'
    });
  }

  res.status(201).json({
    ok: true,
    message: 'First admin device registered.',
    deviceId
  });
});

// Create a one-time invitation for another device
app.post('/api/admin/device-invites', auth, adminOnly, async (_req, res) => {
  const code = crypto.randomBytes(32).toString('hex');

  const invite = {
    hash: hashInvite(code),
    expiresAt: Date.now() + 10 * 60 * 1000,
    createdAt: new Date().toISOString()
  };

  let outcome = 'ok';

  await db.runTransaction(async tx => {
    const snap = await tx.get(sysRef);
    const data = snap.exists ? snap.data() : {};

    const devices = adminDeviceList(data);

    if (!devices.length) {
      outcome = 'none';
      return;
    }

    if (devices.length >= 3) {
      outcome = 'limit';
      return;
    }

    const active = (
      Array.isArray(data.adminInvites)
        ? data.adminInvites
        : []
    ).filter(i => Number(i.expiresAt) > Date.now());

    tx.set(sysRef, {
      adminDevices: devices,
      adminInvites: [...active, invite],
      securityVersion: 2
    }, { merge: true });
  });

  if (outcome === 'none') {
    return res.status(409).json({
      error: 'No enrolled admin device found.'
    });
  }

  if (outcome === 'limit') {
    return res.status(409).json({
      error: 'All 3 admin device slots are in use. Remove a device first.'
    });
  }

  const updated = await sysRef.get();

  res.status(201).json({
    inviteCode: code,
    expiresIn: 600,
    remainingSlots: 3 - updated.data().adminDevices.length
  });
});

// List registered admin devices
app.get('/api/admin/devices', auth, adminOnly, async (_req, res) => {
  const snap = await sysRef.get();
  const data = snap.exists ? snap.data() : {};

  res.json({
    devices: adminDeviceList(data).map(({
      id,
      deviceName,
      enrolledAt,
      enrolledBy
    }) => ({
      id,
      deviceName: deviceName || 'Admin device',
      enrolledAt: enrolledAt || null,
      enrolledBy: enrolledBy || null
    }))
  });
});

// Remove a registered admin device
app.delete('/api/admin/devices/:id', auth, adminOnly, async (req, res) => {
  const id = clean(req.params.id, 80);

  const snap = await sysRef.get();
  const data = snap.exists ? snap.data() : {};

  const currentId =
    clean(req.body?.currentDeviceId, 80) || 'legacy';

  if (id === currentId) {
    return res.status(400).json({
      error: 'You cannot remove the device you are currently using.'
    });
  }

  const devices = adminDeviceList(data);

  if (!devices.some(d => d.id === id)) {
    return res.status(404).json({
      error: 'Device not found.'
    });
  }

  await sysRef.set({
    adminDevices: devices.filter(d => d.id !== id),
    securityVersion: 2
  }, { merge: true });

  res.json({ ok: true });
});

// Classes
app.get('/api/classes', auth, async (_req, res) => {
  const s = await db.collection('classes')
    .orderBy('name')
    .get();

  res.json({
    classes: s.docs.map(d => ({
      id: d.id,
      ...d.data()
    }))
  });
});

// Students
app.get('/api/students', auth, async (req, res) => {
  let q = db.collection('students');

  if (req.query.classId) {
    q = q.where(
      'classId',
      '==',
      clean(req.query.classId, 128)
    );
  }

  const s = await q.get();

  res.json({
    students: s.docs.map(d => ({
      id: d.id,
      ...d.data()
    }))
  });
});

// Attendance records
app.get('/api/attendance', auth, async (req, res) => {
  const classId = clean(req.query.classId, 128);
  const date = clean(req.query.date, 10);

  if (!classId || !validDate(date)) {
    return res.status(400).json({
      error: 'A class and date within the latest 30 days are required.'
    });
  }

  const s = await db.collection('attendance')
    .where('classId', '==', classId)
    .where('date', '==', date)
    .get();

  res.json({
    records: s.docs.map(d => ({
      id: d.id,
      ...d.data()
    }))
  });
});

// Mark attendance
app.post('/api/attendance', auth, async (req, res) => {
  const classId = clean(req.body?.classId, 128);
  const studentId = clean(req.body?.studentId, 128);
  const date = clean(req.body?.date, 10);
  const status = req.body?.status;

  if (
    !classId ||
    !studentId ||
    !validDate(date) ||
    !['Present', 'Absent'].includes(status)
  ) {
    return res.status(400).json({
      error: 'Invalid attendance details.'
    });
  }

  const student = await db.collection('students')
    .doc(studentId)
    .get();

  if (
    !student.exists ||
    student.data().classId !== classId
  ) {
    return res.status(404).json({
      error: 'Student not found in this class.'
    });
  }

  const id = `${classId}_${date}_${studentId}`;

  await db.collection('attendance')
    .doc(id)
    .set({
      classId,
      studentId,
      studentName: student.data().name,
      date,
      status,
      updatedAt: new Date().toISOString(),
      updatedBy: req.session.name
    }, { merge: true });

  res.json({
    ok: true,
    id
  });
});

// Undo attendance
app.delete('/api/attendance/:id', auth, async (req, res) => {
  const id = clean(req.params.id, 300);

  const ref = db.collection('attendance').doc(id);
  const snap = await ref.get();

  if (!snap.exists) {
    return res.json({ ok: true });
  }

  if (
    snap.data().updatedBy !== req.session.name &&
    req.session.role !== 'admin'
  ) {
    return res.status(403).json({
      error: 'You can only undo your own latest mark.'
    });
  }

  await ref.delete();

  res.json({ ok: true });
});

// Add class
app.post('/api/admin/classes', auth, adminOnly, async (req, res) => {
  const name = clean(req.body?.name, 60);

  if (!name) {
    return res.status(400).json({
      error: 'Class name required.'
    });
  }

  const ref = await db.collection('classes').add({
    name,
    studentCount: 0,
    createdAt: new Date().toISOString()
  });

  res.status(201).json({
    id: ref.id,
    name
  });
});

// Delete class
app.delete('/api/admin/classes/:id', auth, adminOnly, async (req, res) => {
  const id = clean(req.params.id, 128);

  const students = await db.collection('students')
    .where('classId', '==', id)
    .get();

  const attendance = await db.collection('attendance')
    .where('classId', '==', id)
    .get();

  if (!students.empty || !attendance.empty) {
    return res.status(409).json({
      error: 'This class still has students or attendance. Remove/move those records first.'
    });
  }

  await db.collection('classes').doc(id).delete();

  res.json({ ok: true });
});

// Add student
app.post('/api/admin/students', auth, adminOnly, async (req, res) => {
  const name = clean(req.body?.name, 80);
  const classId = clean(req.body?.classId, 128);

  if (!name || !classId) {
    return res.status(400).json({
      error: 'Student name and class are required.'
    });
  }

  const c = db.collection('classes').doc(classId);
  const snap = await c.get();

  if (!snap.exists) {
    return res.status(404).json({
      error: 'Class not found.'
    });
  }

  const ref = db.collection('students').doc();
  const batch = db.batch();

  batch.set(ref, {
    name,
    classId,
    createdAt: new Date().toISOString()
  });

  batch.update(c, {
    studentCount: (Number(snap.data().studentCount) || 0) + 1
  });

  await batch.commit();

  res.status(201).json({
    id: ref.id,
    name,
    classId
  });
});

// Delete student while preserving attendance history
app.delete('/api/admin/students/:id', auth, adminOnly, async (req, res) => {
  const id = clean(req.params.id, 128);

  const ref = db.collection('students').doc(id);
  const snap = await ref.get();

  if (!snap.exists) {
    return res.status(404).json({
      error: 'Student not found.'
    });
  }

  const data = snap.data();

  const attendance = await db.collection('attendance')
    .where('studentId', '==', id)
    .get();

  const batch = db.batch();

  batch.delete(ref);

  const c = db.collection('classes').doc(data.classId);
  const cs = await c.get();

  if (cs.exists) {
    batch.update(c, {
      studentCount: Math.max(
        0,
        (Number(cs.data().studentCount) || 1) - 1
      )
    });
  }

  await batch.commit();

  res.json({
    ok: true,
    preservedAttendance: attendance.size
  });
});

// Admin dashboard summary
app.get('/api/admin/summary', auth, adminOnly, async (_req, res) => {
  const [c, s, a] = await Promise.all([
    db.collection('classes').get(),
    db.collection('students').get(),
    db.collection('attendance').get()
  ]);

  res.json({
    classes: c.size,
    students: s.size,
    attendanceRecords: a.size
  });
});

// Error handler
app.use((err, _req, res, _next) => {
  console.error('API error:', err.message);

  res.status(500).json({
    error: 'Server error. Please try again.'
  });
});

const port = Number(process.env.PORT) || 10000;

app.listen(port, '0.0.0.0', () => {
  console.log(
    `CCC Students Attendance secure API listening on ${port}`
  );
});
