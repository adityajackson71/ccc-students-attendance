'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');
const { Firestore } = require('@google-cloud/firestore');
const crypto = require('node:crypto');

const required = ['JWT_SECRET', 'TEACHER_PASSWORD_HASH', 'ADMIN_SETUP_CODE', 'FIREBASE_SERVICE_ACCOUNT'];
for (const key of required) if (!process.env[key]) {
  console.error(`Missing required environment variable: ${key}`);
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters.');

let serviceAccount;
try { serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT); }
catch { throw new Error('FIREBASE_SERVICE_ACCOUNT must contain valid JSON.'); }
const db = new Firestore({ projectId: serviceAccount.project_id, credentials: {
  client_email: serviceAccount.client_email,
  private_key: serviceAccount.private_key
}});

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const origins = (process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
console.log('Allowed origins:', origins);
app.use(cors({ origin(origin, cb) {
  if (!origin && process.env.NODE_ENV !== 'production') return cb(null, true);
  if (origins.length > 0 && origins.includes(origin)) return cb(null, true);
  return cb(new Error('Origin not allowed'));
}, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization','X-Device-Signature'] }));
app.use(express.json({ limit: '256kb' }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Try again in 15 minutes.' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
app.use('/api', apiLimiter);

const sysRef = db.collection('system').doc('security');
const challenges = new Map();
const MAX_CHALLENGES = 1000;
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const clean = (v, max=100) => typeof v === 'string' ? v.trim().replace(/[<>\u0000-\u001f]/g, '').slice(0,max) : '';
const validDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s) && s >= (()=>{const d=new Date();d.setDate(d.getDate()-29);return d.toLocaleDateString('en-CA',{timeZone:'Asia/Kolkata'});})() && s <= today();

function tokenFor(role, name) {
  return jwt.sign({ role, name }, process.env.JWT_SECRET, { expiresIn: role === 'admin' ? '2h' : '8h', issuer: 'ccc-attendance' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    if (!h.startsWith('Bearer ')) throw new Error('missing');
    req.session = jwt.verify(h.slice(7), process.env.JWT_SECRET, { issuer: 'ccc-attendance' });
    next();
  } catch { res.status(401).json({ error: 'Please sign in again.' }); }
}
const adminOnly = (req,res,next) => req.session?.role === 'admin' ? next() : res.status(403).json({error:'Admin permission required.'});
async function verifySharedPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) return false;
  return bcrypt.compare(password, process.env.TEACHER_PASSWORD_HASH);
}

app.get('/', (_req,res) => res.json({ status:'ok', service:'CCC Students Attendance secure API', version:'1.0.0' }));
app.get('/health', (_req,res) => res.json({ ok:true }));

// Teacher and admin share the same password. Admin additionally proves possession
// of the private key enrolled on the approved device.
app.post('/api/auth/teacher', loginLimiter, async (req,res) => {
  const name = clean(req.body?.name,60), password = req.body?.password;
  if (!name || !await verifySharedPassword(password)) return res.status(401).json({error:'Name or password is incorrect.'});
  res.json({ token: tokenFor('teacher',name), role:'teacher', name, expiresIn:28800 });
});

app.post('/api/auth/challenge', loginLimiter, async (_req,res) => {
  const challenge = crypto.randomBytes(32).toString('base64url');
  const id = crypto.randomBytes(18).toString('base64url');
  if (challenges.size >= MAX_CHALLENGES) challenges.delete(challenges.keys().next().value);
  challenges.set(id,{challenge, expires:Date.now()+120000});
  res.json({ challengeId:id, challenge });
});

app.post('/api/auth/admin', loginLimiter, async (req,res) => {
  const name=clean(req.body?.name,60), password=req.body?.password;
  const { challengeId, signature } = req.body || {};
  if (!name || !await verifySharedPassword(password)) return res.status(401).json({error:'Name or password is incorrect.'});
  const c=challenges.get(challengeId); challenges.delete(challengeId);
  if (!c || c.expires<Date.now() || typeof signature!=='string') return res.status(401).json({error:'Device verification expired. Try again.'});
  const snap=await sysRef.get(); const device=snap.exists?snap.data().adminDevice:null;
  if (!device?.publicJwk) return res.status(403).json({error:'Admin device has not been registered. Complete first-time setup.'});
  try {
    const pub=crypto.createPublicKey({key:device.publicJwk,format:'jwk'});
    const ok=crypto.verify('sha256',Buffer.from(c.challenge),{key:pub,dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url'));
    if (!ok) return res.status(403).json({error:'This is not the approved admin device.'});
  } catch { return res.status(400).json({error:'Invalid device proof.'}); }
  res.json({token:tokenFor('admin',name),role:'admin',name,expiresIn:7200});
});

// One-time device enrollment. Keep ADMIN_SETUP_CODE private in Render. This route
// can only run once; recovery requires a deliberate server-side reset by owner.
app.post('/api/admin/enroll-device', loginLimiter, async (req,res) => {
  const name=clean(req.body?.name,60), password=req.body?.password;
  const setupCode=req.body?.setupCode, publicJwk=req.body?.publicJwk;
  if (!name || !await verifySharedPassword(password)) return res.status(401).json({error:'Name or password is incorrect.'});
  if (typeof setupCode!=='string' || setupCode.length < 20 || setupCode.length > 256 || setupCode.length !== process.env.ADMIN_SETUP_CODE.length || !crypto.timingSafeEqual(Buffer.from(setupCode),Buffer.from(process.env.ADMIN_SETUP_CODE))) return res.status(403).json({error:'Invalid setup code.'});
  if (!publicJwk || publicJwk.kty!=='EC' || publicJwk.crv!=='P-256' || !publicJwk.x || !publicJwk.y || publicJwk.d) return res.status(400).json({error:'A valid public P-256 key is required. Never send a private key.'});
  try { crypto.createPublicKey({key:publicJwk,format:'jwk'}); } catch { return res.status(400).json({error:'Invalid public key.'}); }
  await db.runTransaction(async tx=>{
    const snap=await tx.get(sysRef);
    if (snap.exists && (snap.data().adminDevice || snap.data().setupCodeUsed)) throw new Error('ADMIN_DEVICE_ALREADY_ENROLLED');
    tx.set(sysRef,{adminDevice:{publicJwk, enrolledAt:new Date().toISOString(), enrolledBy:name},setupCodeUsed:true,securityVersion:1},{merge:true});
  }).catch(err=>{ if(err.message==='ADMIN_DEVICE_ALREADY_ENROLLED') return res.status(409).json({error:'An admin device is already registered. Contact the owner for recovery.'}); throw err; });
  if (res.headersSent) return;
  res.status(201).json({ok:true,message:'This device is now the registered admin device. Store your recovery code safely.'});
});

app.get('/api/classes',auth,async(_req,res)=>{const s=await db.collection('classes').orderBy('name').get();res.json({classes:s.docs.map(d=>({id:d.id,...d.data()}))});});
app.get('/api/students',auth,async(req,res)=>{let q=db.collection('students');if(req.query.classId)q=q.where('classId','==',clean(req.query.classId,128));const s=await q.get();res.json({students:s.docs.map(d=>({id:d.id,...d.data()}))});});
app.get('/api/attendance',auth,async(req,res)=>{const classId=clean(req.query.classId,128),date=clean(req.query.date,10);if(!classId||!validDate(date))return res.status(400).json({error:'A class and date within the latest 30 days are required.'});const s=await db.collection('attendance').where('classId','==',classId).where('date','==',date).get();res.json({records:s.docs.map(d=>({id:d.id,...d.data()}))});});
app.post('/api/attendance',auth,async(req,res)=>{const classId=clean(req.body?.classId,128),studentId=clean(req.body?.studentId,128),date=clean(req.body?.date,10),status=req.body?.status;if(!classId||!studentId||!validDate(date)||!['Present','Absent'].includes(status))return res.status(400).json({error:'Invalid attendance details.'});const student=await db.collection('students').doc(studentId).get();if(!student.exists||student.data().classId!==classId)return res.status(404).json({error:'Student not found in this class.'});const id=`${classId}_${date}_${studentId}`;await db.collection('attendance').doc(id).set({classId,studentId,studentName:student.data().name,date,status,updatedAt:new Date().toISOString(),updatedBy:req.session.name},{merge:true});res.json({ok:true,id});});
app.delete('/api/attendance/:id',auth,async(req,res)=>{const id=clean(req.params.id,300);const ref=db.collection('attendance').doc(id);const snap=await ref.get();if(!snap.exists)return res.json({ok:true});if(snap.data().updatedBy!==req.session.name && req.session.role!=='admin')return res.status(403).json({error:'You can only undo your own latest mark.'});await ref.delete();res.json({ok:true});});

app.post('/api/admin/classes',auth,adminOnly,async(req,res)=>{const name=clean(req.body?.name,60);if(!name)return res.status(400).json({error:'Class name required.'});const ref=await db.collection('classes').add({name,studentCount:0,createdAt:new Date().toISOString()});res.status(201).json({id:ref.id,name});});
app.delete('/api/admin/classes/:id',auth,adminOnly,async(req,res)=>{const id=clean(req.params.id,128);const students=await db.collection('students').where('classId','==',id).get();const attendance=await db.collection('attendance').where('classId','==',id).get();if(!students.empty||!attendance.empty)return res.status(409).json({error:'This class still has students or attendance. Remove/move those records first.'});await db.collection('classes').doc(id).delete();res.json({ok:true});});
app.post('/api/admin/students',auth,adminOnly,async(req,res)=>{const name=clean(req.body?.name,80),classId=clean(req.body?.classId,128);if(!name||!classId)return res.status(400).json({error:'Student name and class are required.'});const c=db.collection('classes').doc(classId);const snap=await c.get();if(!snap.exists)return res.status(404).json({error:'Class not found.'});const ref=db.collection('students').doc();const batch=db.batch();batch.set(ref,{name,classId,createdAt:new Date().toISOString()});batch.update(c,{studentCount: (Number(snap.data().studentCount)||0)+1});await batch.commit();res.status(201).json({id:ref.id,name,classId});});
app.delete('/api/admin/students/:id',auth,adminOnly,async(req,res)=>{const id=clean(req.params.id,128),ref=db.collection('students').doc(id),snap=await ref.get();if(!snap.exists)return res.status(404).json({error:'Student not found.'});const data=snap.data();const attendance=await db.collection('attendance').where('studentId','==',id).get();const batch=db.batch();batch.delete(ref);const c=db.collection('classes').doc(data.classId),cs=await c.get();if(cs.exists)batch.update(c,{studentCount:Math.max(0,(Number(cs.data().studentCount)||1)-1)});await batch.commit();res.json({ok:true,preservedAttendance:attendance.size});});
app.get('/api/admin/summary',auth,adminOnly,async(_req,res)=>{const [c,s,a]=await Promise.all([db.collection('classes').get(),db.collection('students').get(),db.collection('attendance').get()]);res.json({classes:c.size,students:s.size,attendanceRecords:a.size});});

app.use((err,_req,res,_next)=>{console.error('API error:',err.message);res.status(500).json({error:'Server error. Please try again.'});});
const port=Number(process.env.PORT)||10000;
app.listen(port,'0.0.0.0',()=>console.log(`CCC Students Attendance secure API listening on ${port}`));
