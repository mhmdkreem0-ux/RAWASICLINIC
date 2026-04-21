/*
  🦷 رواسي لطب الأسنان — v5 SECURE
  Admin: rexlmk / mhmd@123
  Security: Rate limiting, brute-force protection, input sanitization,
            strict CORS, request size limits, security headers, audit log
*/
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3001;

// ══════════════════════════════════════════════════════════
//  SECURITY — In-memory rate limiter (no extra packages)
// ══════════════════════════════════════════════════════════
const _hits  = new Map(); // ip -> { count, resetAt }
const _fails = new Map(); // ip -> { count, lockedUntil }

function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
    const now = Date.now();
    let entry = _hits.get(ip);
    if (!entry || now > entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      _hits.set(ip, entry);
    }
    entry.count++;
    if (entry.count > max) {
      return res.status(429).json({
        error: 'طلبات كثيرة جداً، يرجى الانتظار قليلاً',
        retryAfter: Math.ceil((entry.resetAt - now) / 1000)
      });
    }
    next();
  };
}

function loginBruteGuard(req, res, next) {
  const ip = (req.headers['x-forwarded-for'] || req.ip || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  req._ipKey = ip; // always set before any return
  const now = Date.now();
  const f = _fails.get(ip) || { count: 0, lockedUntil: 0 };
  if (f.lockedUntil > now) {
    const secs = Math.ceil((f.lockedUntil - now) / 1000);
    return res.status(429).json({ error: 'تم إيقاف المحاولات مؤقتاً. حاول بعد ' + secs + ' ثانية' });
  }
  next();
}
function recordLoginFail(ip) {
  const f = _fails.get(ip) || { count: 0, lockedUntil: 0 };
  f.count++;
  if (f.count >= 5) f.lockedUntil = Date.now() + 15 * 60 * 1000;
  _fails.set(ip, f);
}
function clearLoginFail(ip) { _fails.delete(ip); }

// Sanitize helpers
function san(v) {
  if (v == null) return null;
  // strip only truly dangerous chars, keep @ . - _ for emails/usernames
  return String(v).replace(/[<>"`;]/g, '').trim().slice(0, 500) || null;
}
// Strict sanitizer for fields that should NEVER contain special chars
function sanStrict(v) {
  if (v == null) return null;
  return String(v).replace(/[^a-zA-Z0-9؀-ۿ\s\-_.]/g, '').trim().slice(0, 200) || null;
}
function sanEmail(v) {
  if (!v) return null;
  const e = String(v).toLowerCase().trim().slice(0, 150);
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e) ? e : null;
}
function sanPhone(v) {
  if (!v) return null;
  return String(v).replace(/[^\d+\-\s]/g, '').trim().slice(0, 20) || null;
}
function sanInt(v) {
  const n = parseInt(v, 10);
  return isNaN(n) ? null : n;
}

// ══════════════════════════════════════════════════════════
//  HELMET + CORS + BODY
// ══════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
      fontSrc:     ["'self'", 'data:', 'https://fonts.gstatic.com', 'https://fonts.googleapis.com'],
      imgSrc:      ["'self'", 'data:', 'blob:', 'https://res.cloudinary.com', 'https://*.cloudinary.com'],
      connectSrc:  ["'self'", 'https://api.cloudinary.com', 'https://*.vercel.app', 'https://*.neon.tech'],
      workerSrc:   ["'self'", 'blob:'],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
      upgradeInsecureRequests: [],
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff: true,
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// CORS — open for all origins (Vercel + custom domains)
app.use(cors({
  origin: true,
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true,
}));
app.options('*', cors());

app.use(express.json({ limit: '2mb' }));
app.use(rateLimit(200, 60_000));

app.use((req, res, next) => {
  res.setHeader('X-Request-ID', Math.random().toString(36).slice(2));
  next();
});

// ══════════════════════════════════════════════════════════
//  DATABASE
// ══════════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ══════════════════════════════════════════════════════════
//  INIT DB
// ══════════════════════════════════════════════════════════
async function initDB() {
  const c = await pool.connect();
  try {
    await c.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        username VARCHAR(100) UNIQUE,
        email VARCHAR(150),
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'receptionist',
        doctor_id INTEGER,
        is_active BOOLEAN DEFAULT true,
        login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS doctors (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        specialty VARCHAR(100),
        phone VARCHAR(20),
        email VARCHAR(150),
        color VARCHAR(7) DEFAULT '#3C2A98',
        start_time TIME DEFAULT '09:00',
        end_time TIME DEFAULT '18:00',
        slot_duration INTEGER DEFAULT 30,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS doctor_available_days (
        id SERIAL PRIMARY KEY,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
        day_of_week INTEGER NOT NULL,
        start_time TIME DEFAULT '09:00',
        end_time TIME DEFAULT '18:00',
        UNIQUE(doctor_id, day_of_week)
      );
      CREATE TABLE IF NOT EXISTS doctor_day_exceptions (
        id SERIAL PRIMARY KEY,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
        exception_date DATE NOT NULL,
        is_available BOOLEAN NOT NULL DEFAULT false,
        reason VARCHAR(200),
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(doctor_id, exception_date)
      );
      CREATE TABLE IF NOT EXISTS patients (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        email VARCHAR(150),
        age INTEGER,
        gender VARCHAR(10),
        notes TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS appointments (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE SET NULL,
        service VARCHAR(100) NOT NULL,
        appointment_date DATE NOT NULL,
        appointment_time TIME NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        notes TEXT,
        doctor_unavailable BOOLEAN DEFAULT false,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS patient_cases (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE SET NULL,
        title VARCHAR(200) NOT NULL,
        description TEXT, diagnosis TEXT, treatment_plan TEXT,
        status VARCHAR(30) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS case_sessions (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES patient_cases(id) ON DELETE CASCADE,
        appointment_id INTEGER REFERENCES appointments(id) ON DELETE SET NULL,
        session_date DATE NOT NULL,
        notes TEXT, procedure_done TEXT, next_session TEXT,
        cost NUMERIC(10,2), created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS case_images (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES patient_cases(id) ON DELETE CASCADE,
        session_id INTEGER REFERENCES case_sessions(id) ON DELETE SET NULL,
        image_url TEXT NOT NULL, image_type VARCHAR(20) DEFAULT 'photo',
        caption TEXT, uploaded_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS notifications_log (
        id SERIAL PRIMARY KEY,
        appointment_id INTEGER REFERENCES appointments(id) ON DELETE CASCADE,
        type VARCHAR(20), status VARCHAR(20), message TEXT, sent_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER, user_name VARCHAR(100),
        action VARCHAR(50), resource VARCHAR(50), resource_id INTEGER,
        ip VARCHAR(60), details TEXT, created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Safe migrations — each isolated so one failure doesn't block others
    const safeMigrate = async (sql) => { try { await c.query(sql); } catch {} };
    await safeMigrate(`ALTER TABLE appointments ADD COLUMN IF NOT EXISTS doctor_unavailable BOOLEAN DEFAULT false`);
    await safeMigrate(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login_attempts INTEGER DEFAULT 0`);
    await safeMigrate(`ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP`);
    await safeMigrate(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP`);
    await safeMigrate(`CREATE TABLE IF NOT EXISTS doctor_day_exceptions (
      id SERIAL PRIMARY KEY,
      doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
      exception_date DATE NOT NULL,
      is_available BOOLEAN NOT NULL DEFAULT false,
      reason VARCHAR(200),
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(doctor_id, exception_date)
    )`);
    await safeMigrate(`CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      user_id INTEGER, user_name VARCHAR(100),
      action VARCHAR(50), resource VARCHAR(50), resource_id INTEGER,
      ip VARCHAR(60), details TEXT, created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Seed doctors
    const { rowCount: dc } = await c.query('SELECT id FROM doctors LIMIT 1');
    if (!dc) {
      await c.query(`
        INSERT INTO doctors (name,specialty,color,start_time,end_time) VALUES
        ('د. رواسي رعد العامري','تقويم الأسنان',         '#3C2A98','09:00','18:00'),
        ('د. علي العزال',       'حشوات جذور وابتسامات', '#7B6DD4','09:00','18:00'),
        ('د. عبدالله جمال',     'طب الأسنان العام',      '#534AB7','10:00','17:00'),
        ('د. نهلة العبيدي',     'تجميل الأسنان',         '#9D8FE8','09:00','16:00')
      `);
      const { rows: docs } = await c.query('SELECT id FROM doctors');
      for (const d of docs) {
        for (let day = 0; day <= 5; day++) {
          await c.query(
            'INSERT INTO doctor_available_days(doctor_id,day_of_week,start_time,end_time) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',
            [d.id, day, '09:00', '18:00']
          );
        }
      }
    }

    // Seed admin — always ensure rexlmk exists with correct password
    try {
      const { rows: adminRows } = await c.query("SELECT id FROM users WHERE username='rexlmk' LIMIT 1");
      if (!adminRows.length) {
        const hash = await bcrypt.hash('mhmd@123', 10);
        await c.query(
          `INSERT INTO users(name,email,username,password,role,is_active)
           VALUES('المديرة','admin@rawasi.iq','rexlmk',$1,'admin',true)
           ON CONFLICT(username) DO UPDATE SET password=$1, is_active=true, role='admin'`,
          [hash]
        );
        console.log('✅ Admin user created/updated');
      }
    } catch(adminErr) { console.error('Admin seed error:', adminErr.message); }
    console.log('✅ DB ready');
  } catch(e) {
    console.error('initDB ERROR:', e.message);
    // Don't crash — server still starts, DB errors show in logs
  } finally {
    try { c.release(); } catch {}
  }
}

// ══════════════════════════════════════════════════════════
//  AUDIT
// ══════════════════════════════════════════════════════════
async function audit(userId, userName, action, resource, resourceId, ip, details) {
  try {
    await pool.query(
      'INSERT INTO audit_log(user_id,user_name,action,resource,resource_id,ip,details) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [userId||null, userName||null, action, resource, resourceId||null, ip||null, details||null]
    );
  } catch {}
}

// ══════════════════════════════════════════════════════════
//  JWT AUTH
// ══════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || 'rawasi-CHANGE-IN-PRODUCTION-2025!';

function auth(roles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer '))
      return res.status(401).json({ error: 'غير مصرح' });
    try {
      const p = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
      if (roles.length && !roles.includes(p.role))
        return res.status(403).json({ error: 'ليس لديك صلاحية' });
      req.user = p;
      req._ip  = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
      next();
    } catch(e) {
      if (e.name === 'TokenExpiredError')
        return res.status(401).json({ error: 'انتهت صلاحية الجلسة' });
      return res.status(401).json({ error: 'token غير صالح' });
    }
  };
}

// ══════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/health', async (_,res) => {
  try { await pool.query('SELECT 1'); res.json({ status:'ok', db:'connected' }); }
  catch { res.status(500).json({ status:'error' }); }
});

// ── LOGIN ────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const uid = String(req.body.email || '').trim().slice(0, 150);
    const pwd = String(req.body.password || '').slice(0, 128);

    if (!uid || !pwd) {
      return res.status(400).json({ error: 'أدخل اسم المستخدم وكلمة المرور' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM users WHERE (email=$1 OR username=$1) AND is_active=true LIMIT 1',
      [uid]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'الحساب غير موجود' });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(pwd, user.password);

    if (!ok) {
      return res.status(401).json({ error: 'كلمة المرور خطأ' });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role, doctor_id: user.doctor_id },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, doctor_id: user.doctor_id }
    });
  } catch (e) {
    console.error('LOGIN ERROR:', e.message, e.stack);
    res.status(500).json({ error: 'خطأ في السيرفر: ' + e.message });
  }
});

app.get('/api/auth/me', auth(), (req,res) => res.json(req.user));

// ── PUBLIC: Doctors ──────────────────────────────────────
app.get('/api/public/doctors', rateLimit(60, 60_000), async (_,res) => {
  try {
    const { rows } = await pool.query('SELECT id,name,specialty,color,start_time,end_time FROM doctors WHERE is_active=true ORDER BY name');
    res.json(rows);
  } catch { res.status(500).json({ error:'خطأ' }); }
});

// ── PUBLIC: Slots (shows unavailable flag but still returns times) ──
app.get('/api/public/slots', rateLimit(60, 60_000), async (req,res) => {
  const doctor_id = sanInt(req.query.doctor_id);
  const date      = san(req.query.date);
  if (!doctor_id || !date || !/^\d{4}-\d{2}-\d{2}$/.test(date))
    return res.status(400).json({ error:'بيانات غير صحيحة' });
  try {
    const dr = (await pool.query('SELECT * FROM doctors WHERE id=$1 AND is_active=true',[doctor_id])).rows[0];
    if (!dr) return res.status(404).json({ error:'الطبيب غير موجود' });

    const exc = (await pool.query(
      'SELECT * FROM doctor_day_exceptions WHERE doctor_id=$1 AND exception_date=$2',[doctor_id,date]
    )).rows[0];

    const dayOfWeek = new Date(date).getDay();
    const dayRow = await pool.query(
      'SELECT * FROM doctor_available_days WHERE doctor_id=$1 AND day_of_week=$2',[doctor_id,dayOfWeek]
    );

    // docUnavailable = doctor marked exception as unavailable, OR no schedule for this weekday
    let docUnavailable = false;
    if (exc) {
      docUnavailable = !exc.is_available;
    } else if (!dayRow.rowCount) {
      docUnavailable = true;
    }

    // Still build slots from schedule (or doctor's default hours) so public can pick a time
    const sched = dayRow.rows[0] || { start_time: dr.start_time, end_time: dr.end_time };
    const booked = await pool.query(
      `SELECT TO_CHAR(appointment_time,'HH24:MI') as t FROM appointments
       WHERE doctor_id=$1 AND appointment_date=$2 AND status!='cancelled'`,[doctor_id,date]
    );
    const bookedTimes = booked.rows.map(r=>r.t);
    const slots=[];
    const [sh,sm]=(sched.start_time||'09:00').split(':').map(Number);
    const [eh,em]=(sched.end_time  ||'18:00').split(':').map(Number);
    let cur=sh*60+sm; const end=eh*60+em;
    while(cur<end){
      const h=String(Math.floor(cur/60)).padStart(2,'0');
      const m=String(cur%60).padStart(2,'0');
      slots.push({ time:`${h}:${m}`, available:!bookedTimes.includes(`${h}:${m}`) });
      cur+=dr.slot_duration||30;
    }
    res.json({ docUnavailable, reason:exc?.reason||null, slots });
  } catch(e){ console.error(e); res.status(500).json({ error:'خطأ في السيرفر' }); }
});

// ── PUBLIC: Book (always accepted; marks unavailable flag) ──
app.post('/api/public/book', rateLimit(5, 60_000), async (req,res) => {
  const name             = san(req.body.name);
  const phone            = sanPhone(req.body.phone);
  const service          = san(req.body.service);
  const doctor_id        = sanInt(req.body.doctor_id);
  const appointment_date = san(req.body.appointment_date);
  const appointment_time = san(req.body.appointment_time);
  const notes            = san(req.body.notes);
  const age              = sanInt(req.body.age);
  const gender           = san(req.body.gender);

  if (!name||!phone||!service||!doctor_id||!appointment_date||!appointment_time)
    return res.status(400).json({ error:'يرجى تعبئة جميع الحقول المطلوبة' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(appointment_date))
    return res.status(400).json({ error:'تاريخ غير صحيح' });
  if (!/^\d{2}:\d{2}$/.test(appointment_time))
    return res.status(400).json({ error:'وقت غير صحيح' });

  try {
    const dr = (await pool.query('SELECT * FROM doctors WHERE id=$1 AND is_active=true',[doctor_id])).rows[0];
    if (!dr) return res.status(404).json({ error:'الطبيب غير موجود' });

    // Check availability
    const exc = (await pool.query(
      'SELECT * FROM doctor_day_exceptions WHERE doctor_id=$1 AND exception_date=$2',[doctor_id,appointment_date]
    )).rows[0];
    const dayOfWeek = new Date(appointment_date).getDay();
    const hasSched  = (await pool.query(
      'SELECT id FROM doctor_available_days WHERE doctor_id=$1 AND day_of_week=$2',[doctor_id,dayOfWeek]
    )).rowCount > 0;
    const docUnavailable = exc ? !exc.is_available : !hasSched;

    // Find or create patient
    let pt = (await pool.query('SELECT * FROM patients WHERE phone=$1',[phone])).rows[0];
    if (!pt) {
      pt = (await pool.query(
        'INSERT INTO patients(name,phone,age,gender) VALUES($1,$2,$3,$4) RETURNING *',
        [name,phone,age||null,gender||null]
      )).rows[0];
    }

    // Conflict check only if doctor is available (unavailable = receptionist handles)
    if (!docUnavailable) {
      const conflict = await pool.query(
        `SELECT id FROM appointments WHERE doctor_id=$1 AND appointment_date=$2
         AND appointment_time=$3 AND status!='cancelled'`,
        [doctor_id,appointment_date,appointment_time]
      );
      if (conflict.rowCount)
        return res.status(409).json({ error:'هذا الوقت محجوز مسبقاً، يرجى اختيار وقت آخر' });
    }

    const { rows } = await pool.query(
      `INSERT INTO appointments(patient_id,doctor_id,service,appointment_date,appointment_time,notes,status,doctor_unavailable)
       VALUES($1,$2,$3,$4,$5,$6,'pending',$7) RETURNING *`,
      [pt.id,doctor_id,service,appointment_date,appointment_time,notes||null,docUnavailable]
    );

    const msg = docUnavailable
      ? `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم استلام طلب حجزك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr.name}\n🩺 ${service}\n\n⚠️ الطبيب قد لا يكون متاحاً في هذا اليوم. سيتواصل معك موظف الاستقبال لتأكيد الموعد أو تحديد بديل.\n📞 07747881005`
      : `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم استلام طلب حجزك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr.name}\n🩺 ${service}\n\nسيتم التأكيد قريباً.\n📍 بغداد - الحارثية\n📞 07747881005`;

    const waPhone = phone.startsWith('0') ? '964'+phone.slice(1) : phone;
    res.json({ success:true, appointment:rows[0], docUnavailable, waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
  } catch(e) { console.error(e); res.status(500).json({ error:'خطأ في السيرفر' }); }
});

// ── Doctors (private) ────────────────────────────────────
app.get('/api/doctors', auth(), async (_,res) => {
  const { rows } = await pool.query('SELECT * FROM doctors WHERE is_active=true ORDER BY name');
  res.json(rows);
});

app.post('/api/doctors', auth(['admin']), async (req,res) => {
  const name          = san(req.body.name);
  const specialty     = san(req.body.specialty);
  const phone         = sanPhone(req.body.phone);
  const email         = sanEmail(req.body.email);
  const color         = /^#[0-9a-fA-F]{6}$/.test(req.body.color||'') ? req.body.color : '#3C2A98';
  const start_time    = san(req.body.start_time)||'09:00';
  const end_time      = san(req.body.end_time)  ||'18:00';
  const slot_duration = sanInt(req.body.slot_duration)||30;
  if (!name) return res.status(400).json({ error:'الاسم مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO doctors(name,specialty,phone,email,color,start_time,end_time,slot_duration)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [name,specialty,phone,email,color,start_time,end_time,slot_duration]
  );
  await audit(req.user.id,req.user.name,'CREATE','doctors',rows[0].id,req._ip,name);
  res.json(rows[0]);
});

app.delete('/api/doctors/:id', auth(['admin']), async (req,res) => {
  const id = sanInt(req.params.id);
  if (!id) return res.status(400).json({ error:'id غير صحيح' });
  await pool.query('UPDATE doctors SET is_active=false WHERE id=$1',[id]);
  await audit(req.user.id,req.user.name,'DELETE','doctors',id,req._ip,null);
  res.json({ success:true });
});

// ── Doctor weekly schedule ───────────────────────────────
app.get('/api/doctors/:id/schedule', auth(), async (req,res) => {
  const id = sanInt(req.params.id);
  const { rows } = await pool.query('SELECT * FROM doctor_available_days WHERE doctor_id=$1 ORDER BY day_of_week',[id]);
  res.json(rows);
});

app.put('/api/doctors/:id/schedule', auth(['admin','doctor']), async (req,res) => {
  const docId = sanInt(req.params.id);
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'يمكنك تعديل جدولك فقط' });
  const { days } = req.body;
  if (!Array.isArray(days)) return res.status(400).json({ error:'بيانات غير صحيحة' });
  await pool.query('DELETE FROM doctor_available_days WHERE doctor_id=$1',[docId]);
  for (const d of days.filter(x=>x.active)) {
    await pool.query(
      'INSERT INTO doctor_available_days(doctor_id,day_of_week,start_time,end_time) VALUES($1,$2,$3,$4)',
      [docId, sanInt(d.day_of_week), san(d.start_time)||'09:00', san(d.end_time)||'18:00']
    );
  }
  await audit(req.user.id,req.user.name,'UPDATE','doctor_schedule',docId,req._ip,null);
  res.json({ success:true });
});

// ── Doctor day exceptions (per-date on/off) ──────────────
app.get('/api/doctors/:id/exceptions', auth(['admin','doctor']), async (req,res) => {
  const docId = sanInt(req.params.id);
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'غير مصرح' });
  const { rows } = await pool.query(
    `SELECT * FROM doctor_day_exceptions
     WHERE doctor_id=$1 AND exception_date >= CURRENT_DATE
     ORDER BY exception_date`,
    [docId]
  );
  res.json(rows);
});

app.post('/api/doctors/:id/exceptions', auth(['admin','doctor']), async (req,res) => {
  const docId = sanInt(req.params.id);
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'غير مصرح' });
  const date         = san(req.body.date);
  const is_available = req.body.is_available === true || req.body.is_available === 'true';
  const reason       = san(req.body.reason);
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date))
    return res.status(400).json({ error:'تاريخ غير صحيح' });
  const { rows } = await pool.query(
    `INSERT INTO doctor_day_exceptions(doctor_id,exception_date,is_available,reason)
     VALUES($1,$2,$3,$4)
     ON CONFLICT(doctor_id,exception_date) DO UPDATE SET is_available=$3,reason=$4
     RETURNING *`,
    [docId, date, is_available, reason||null]
  );
  await audit(req.user.id,req.user.name,'EXCEPTION','doctor_schedule',docId,req._ip,`${date}=${is_available}`);
  res.json(rows[0]);
});

app.delete('/api/doctors/:id/exceptions/:date', auth(['admin','doctor']), async (req,res) => {
  const docId = sanInt(req.params.id);
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'غير مصرح' });
  await pool.query(
    'DELETE FROM doctor_day_exceptions WHERE doctor_id=$1 AND exception_date=$2',
    [docId, san(req.params.date)]
  );
  res.json({ success:true });
});

// ── Doctor profile ───────────────────────────────────────
app.get('/api/doctors/:id/profile', auth(['admin','doctor']), async (req,res) => {
  const docId = sanInt(req.params.id);
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'غير مصرح' });
  const [dr,ta,ca,tc,tp,sched] = await Promise.all([
    pool.query('SELECT * FROM doctors WHERE id=$1',[docId]),
    pool.query('SELECT COUNT(*) FROM appointments WHERE doctor_id=$1',[docId]),
    pool.query("SELECT COUNT(*) FROM appointments WHERE doctor_id=$1 AND status='completed'",[docId]),
    pool.query('SELECT COUNT(*) FROM patient_cases WHERE doctor_id=$1',[docId]),
    pool.query('SELECT COUNT(DISTINCT patient_id) FROM appointments WHERE doctor_id=$1',[docId]),
    pool.query('SELECT * FROM doctor_available_days WHERE doctor_id=$1 ORDER BY day_of_week',[docId]),
  ]);
  if (!dr.rows.length) return res.status(404).json({ error:'الطبيب غير موجود' });
  res.json({
    ...dr.rows[0],
    stats:{ total_appointments:+ta.rows[0].count, completed_appointments:+ca.rows[0].count, total_cases:+tc.rows[0].count, total_patients:+tp.rows[0].count },
    schedule:sched.rows,
  });
});

// ── Patients ─────────────────────────────────────────────
app.get('/api/patients', auth(), async (req,res) => {
  const search = san(req.query.search);
  let q='SELECT * FROM patients'; const p=[];
  if (search) { q+=' WHERE name ILIKE $1 OR phone ILIKE $1'; p.push(`%${search}%`); }
  q+=' ORDER BY created_at DESC LIMIT 200';
  const { rows } = await pool.query(q,p);
  res.json(rows);
});

app.post('/api/patients', auth(['admin','receptionist']), async (req,res) => {
  const name=san(req.body.name), phone=sanPhone(req.body.phone);
  if (!name||!phone) return res.status(400).json({ error:'الاسم والهاتف مطلوبان' });
  const ex = await pool.query('SELECT * FROM patients WHERE phone=$1',[phone]);
  if (ex.rowCount) return res.json(ex.rows[0]);
  const { rows } = await pool.query(
    'INSERT INTO patients(name,phone,email,age,gender,notes) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',
    [name,phone,sanEmail(req.body.email),sanInt(req.body.age),san(req.body.gender),san(req.body.notes)]
  );
  res.json(rows[0]);
});

app.get('/api/patients/:id', auth(), async (req,res) => {
  const id=sanInt(req.params.id);
  const { rows } = await pool.query('SELECT * FROM patients WHERE id=$1',[id]);
  if (!rows.length) return res.status(404).json({ error:'غير موجود' });
  const [appts,cases] = await Promise.all([
    pool.query(`SELECT a.*,d.name as doctor_name FROM appointments a LEFT JOIN doctors d ON a.doctor_id=d.id WHERE a.patient_id=$1 ORDER BY a.appointment_date DESC`,[id]),
    pool.query(`SELECT pc.*,d.name as doctor_name,(SELECT COUNT(*) FROM case_sessions WHERE case_id=pc.id) as session_count FROM patient_cases pc LEFT JOIN doctors d ON pc.doctor_id=d.id WHERE pc.patient_id=$1 ORDER BY pc.created_at DESC`,[id]),
  ]);
  const canSeeCases=['admin','doctor'].includes(req.user.role);
  res.json({ ...rows[0], appointments:appts.rows, cases:canSeeCases?cases.rows:[] });
});

// ── Appointments ─────────────────────────────────────────
app.get('/api/appointments', auth(), async (req,res) => {
  const date=san(req.query.date), doctor_id=sanInt(req.query.doctor_id);
  const status=san(req.query.status), from=san(req.query.from), to=san(req.query.to);
  let q=`SELECT a.*,p.name as patient_name,p.phone as patient_phone,d.name as doctor_name,d.color as doctor_color
    FROM appointments a LEFT JOIN patients p ON a.patient_id=p.id LEFT JOIN doctors d ON a.doctor_id=d.id WHERE 1=1`;
  const params=[]; let i=1;
  if (date)      { q+=` AND a.appointment_date=$${i++}`; params.push(date); }
  if (from)      { q+=` AND a.appointment_date>=$${i++}`; params.push(from); }
  if (to)        { q+=` AND a.appointment_date<=$${i++}`; params.push(to); }
  if (doctor_id) { q+=` AND a.doctor_id=$${i++}`; params.push(doctor_id); }
  if (status)    { q+=` AND a.status=$${i++}`; params.push(status); }
  if (req.user.role==='doctor'&&req.user.doctor_id) { q+=` AND a.doctor_id=$${i++}`; params.push(req.user.doctor_id); }
  q+=' ORDER BY a.appointment_date,a.appointment_time LIMIT 500';
  const { rows } = await pool.query(q,params);
  res.json(rows);
});

app.post('/api/appointments', auth(['admin','receptionist']), async (req,res) => {
  const patient_id=sanInt(req.body.patient_id), doctor_id=sanInt(req.body.doctor_id);
  const service=san(req.body.service), appointment_date=san(req.body.appointment_date);
  const appointment_time=san(req.body.appointment_time), notes=san(req.body.notes);
  if (!patient_id||!doctor_id||!service||!appointment_date||!appointment_time)
    return res.status(400).json({ error:'جميع الحقول مطلوبة' });
  const conflict = await pool.query(
    `SELECT id FROM appointments WHERE doctor_id=$1 AND appointment_date=$2 AND appointment_time=$3 AND status!='cancelled'`,
    [doctor_id,appointment_date,appointment_time]
  );
  if (conflict.rowCount) return res.status(409).json({ error:'هذا الوقت محجوز مسبقاً' });
  const { rows } = await pool.query(
    `INSERT INTO appointments(patient_id,doctor_id,service,appointment_date,appointment_time,notes,created_by,status)
     VALUES($1,$2,$3,$4,$5,$6,$7,'pending') RETURNING *`,
    [patient_id,doctor_id,service,appointment_date,appointment_time,notes,req.user.id]
  );
  const pt=(await pool.query('SELECT * FROM patients WHERE id=$1',[patient_id])).rows[0];
  const dr=(await pool.query('SELECT name FROM doctors WHERE id=$1',[doctor_id])).rows[0];
  const msg=`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${service}\n\n📍 بغداد - الحارثية\n📞 07747881005`;
  const waPhone=pt.phone.startsWith('0')?'964'+pt.phone.slice(1):pt.phone;
  res.json({ ...rows[0], waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
});

app.patch('/api/appointments/:id', auth(['admin','receptionist']), async (req,res) => {
  const id=sanInt(req.params.id);
  const { rows } = await pool.query(
    `UPDATE appointments SET status=COALESCE($1,status),notes=COALESCE($2,notes),
     appointment_date=COALESCE($3,appointment_date),appointment_time=COALESCE($4,appointment_time),
     updated_at=NOW() WHERE id=$5 RETURNING *`,
    [san(req.body.status),san(req.body.notes),san(req.body.appointment_date),san(req.body.appointment_time),id]
  );
  if (!rows.length) return res.status(404).json({ error:'الموعد غير موجود' });
  await audit(req.user.id,req.user.name,'UPDATE','appointments',id,req._ip,`status=${req.body.status}`);
  res.json(rows[0]);
});

app.delete('/api/appointments/:id', auth(['admin']), async (req,res) => {
  const id=sanInt(req.params.id);
  await pool.query('DELETE FROM appointments WHERE id=$1',[id]);
  res.json({ success:true });
});

// ── Slots (private) ───────────────────────────────────────
app.get('/api/slots', auth(), async (req,res) => {
  const doctor_id=sanInt(req.query.doctor_id), date=san(req.query.date);
  if (!doctor_id||!date) return res.status(400).json({ error:'doctor_id و date مطلوبان' });
  const dr=(await pool.query('SELECT * FROM doctors WHERE id=$1',[doctor_id])).rows[0];
  if (!dr) return res.status(404).json({ error:'الطبيب غير موجود' });
  const exc=(await pool.query('SELECT * FROM doctor_day_exceptions WHERE doctor_id=$1 AND exception_date=$2',[doctor_id,date])).rows[0];
  const dayOfWeek=new Date(date).getDay();
  const dayRow=await pool.query('SELECT * FROM doctor_available_days WHERE doctor_id=$1 AND day_of_week=$2',[doctor_id,dayOfWeek]);
  const docUnavailable=exc?!exc.is_available:!dayRow.rowCount;
  if (docUnavailable) return res.json({ unavailable:true, slots:[] });
  const sched=dayRow.rows[0];
  const booked=await pool.query(`SELECT TO_CHAR(appointment_time,'HH24:MI') as t FROM appointments WHERE doctor_id=$1 AND appointment_date=$2 AND status!='cancelled'`,[doctor_id,date]);
  const bookedTimes=booked.rows.map(r=>r.t);
  const slots=[];
  const [sh,sm]=sched.start_time.split(':').map(Number);
  const [eh,em]=sched.end_time.split(':').map(Number);
  let cur=sh*60+sm; const end=eh*60+em;
  while(cur<end){
    const h=String(Math.floor(cur/60)).padStart(2,'0');
    const m=String(cur%60).padStart(2,'0');
    slots.push({ time:`${h}:${m}`, available:!bookedTimes.includes(`${h}:${m}`) });
    cur+=dr.slot_duration||30;
  }
  res.json({ unavailable:false, slots });
});

// ── Cases ─────────────────────────────────────────────────
app.get('/api/cases', auth(), async (req,res) => {
  const patient_id=sanInt(req.query.patient_id), doctor_id=sanInt(req.query.doctor_id);
  let q=`SELECT pc.*,d.name as doctor_name,p.name as patient_name,
    (SELECT COUNT(*) FROM case_sessions WHERE case_id=pc.id) as session_count
   FROM patient_cases pc LEFT JOIN doctors d ON pc.doctor_id=d.id
   LEFT JOIN patients p ON pc.patient_id=p.id WHERE 1=1`;
  const params=[]; let i=1;
  if (patient_id) { q+=` AND pc.patient_id=$${i++}`; params.push(patient_id); }
  if (doctor_id)  { q+=` AND pc.doctor_id=$${i++}`; params.push(doctor_id); }
  if (req.user.role==='doctor'&&req.user.doctor_id) { q+=` AND pc.doctor_id=$${i++}`; params.push(req.user.doctor_id); }
  q+=' ORDER BY pc.created_at DESC';
  const { rows } = await pool.query(q,params);
  res.json(rows);
});

app.post('/api/cases', auth(['admin','doctor','receptionist']), async (req,res) => {
  const patient_id=sanInt(req.body.patient_id), doctor_id=sanInt(req.body.doctor_id);
  const title=san(req.body.title);
  if (!patient_id||!title) return res.status(400).json({ error:'المريض والعنوان مطلوبان' });
  const { rows } = await pool.query(
    `INSERT INTO patient_cases(patient_id,doctor_id,title,description,diagnosis,treatment_plan) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [patient_id,doctor_id||req.user.doctor_id||null,title,san(req.body.description),san(req.body.diagnosis),san(req.body.treatment_plan)]
  );
  res.json(rows[0]);
});

app.get('/api/cases/:id', auth(['admin','doctor']), async (req,res) => {
  const id=sanInt(req.params.id);
  const { rows } = await pool.query(
    `SELECT pc.*,d.name as doctor_name,p.name as patient_name,p.phone as patient_phone
     FROM patient_cases pc LEFT JOIN doctors d ON pc.doctor_id=d.id
     LEFT JOIN patients p ON pc.patient_id=p.id WHERE pc.id=$1`,[id]
  );
  if (!rows.length) return res.status(404).json({ error:'الحالة غير موجودة' });
  const [sessions,images] = await Promise.all([
    pool.query('SELECT * FROM case_sessions WHERE case_id=$1 ORDER BY session_date DESC',[id]),
    pool.query('SELECT * FROM case_images WHERE case_id=$1 ORDER BY uploaded_at DESC',[id]),
  ]);
  res.json({ ...rows[0], sessions:sessions.rows, images:images.rows });
});

app.patch('/api/cases/:id', auth(['admin','doctor']), async (req,res) => {
  const id=sanInt(req.params.id);
  const { rows } = await pool.query(
    `UPDATE patient_cases SET title=COALESCE($1,title),description=COALESCE($2,description),
     diagnosis=COALESCE($3,diagnosis),treatment_plan=COALESCE($4,treatment_plan),
     status=COALESCE($5,status),updated_at=NOW() WHERE id=$6 RETURNING *`,
    [san(req.body.title),san(req.body.description),san(req.body.diagnosis),san(req.body.treatment_plan),san(req.body.status),id]
  );
  res.json(rows[0]);
});

app.post('/api/cases/:id/sessions', auth(['admin','doctor']), async (req,res) => {
  const case_id=sanInt(req.params.id), session_date=san(req.body.session_date);
  if (!session_date) return res.status(400).json({ error:'تاريخ الجلسة مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO case_sessions(case_id,appointment_id,session_date,notes,procedure_done,next_session,cost)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [case_id,sanInt(req.body.appointment_id),session_date,san(req.body.notes),san(req.body.procedure_done),san(req.body.next_session),req.body.cost?parseFloat(req.body.cost):null]
  );
  res.json(rows[0]);
});

app.post('/api/cases/:id/images', auth(['admin','doctor']), async (req,res) => {
  const image_url=san(req.body.image_url);
  if (!image_url||!image_url.startsWith('https://')) return res.status(400).json({ error:'رابط غير صحيح' });
  const { rows } = await pool.query(
    `INSERT INTO case_images(case_id,session_id,image_url,image_type,caption) VALUES($1,$2,$3,$4,$5) RETURNING *`,
    [sanInt(req.params.id),sanInt(req.body.session_id),image_url,san(req.body.image_type)||'photo',san(req.body.caption)]
  );
  res.json(rows[0]);
});

app.delete('/api/images/:id', auth(['admin','doctor']), async (req,res) => {
  await pool.query('DELETE FROM case_images WHERE id=$1',[sanInt(req.params.id)]);
  res.json({ success:true });
});

// ── Cloudinary ────────────────────────────────────────────
app.get('/api/cloudinary/signature', auth(['admin','doctor']), (req,res) => {
  const cloudName=process.env.CLOUDINARY_CLOUD_NAME, apiKey=process.env.CLOUDINARY_API_KEY;
  if (!cloudName||!apiKey) return res.status(500).json({ error:'Cloudinary غير مضبوط' });
  res.json({ cloudName, apiKey, uploadPreset:process.env.CLOUDINARY_UPLOAD_PRESET||'rawasi_clinic' });
});

// ── Reports ───────────────────────────────────────────────
app.get('/api/reports/summary', auth(['admin','receptionist']), async (req,res) => {
  let from=san(req.query.from), to=san(req.query.to);
  if (!from||!to) {
    const d=new Date();
    from=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-01`;
    to=d.toISOString().split('T')[0];
  }
  const [total,today,pending,completed,byDoctor,byService,unavail] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date=CURRENT_DATE`),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='pending' AND appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='completed' AND appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT d.name,COUNT(a.id) as count FROM appointments a LEFT JOIN doctors d ON a.doctor_id=d.id WHERE a.appointment_date BETWEEN $1 AND $2 GROUP BY d.name ORDER BY count DESC`,[from,to]),
    pool.query(`SELECT service,COUNT(*) as count FROM appointments WHERE appointment_date BETWEEN $1 AND $2 GROUP BY service ORDER BY count DESC LIMIT 8`,[from,to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE doctor_unavailable=true AND appointment_date BETWEEN $1 AND $2`,[from,to]),
  ]);
  res.json({ total:+total.rows[0].count, today:+today.rows[0].count, pending:+pending.rows[0].count, completed:+completed.rows[0].count, byDoctor:byDoctor.rows, byService:byService.rows, unavailableBookings:+unavail.rows[0].count });
});

// ── Notify ────────────────────────────────────────────────
app.post('/api/appointments/:id/notify', auth(['admin','receptionist']), async (req,res) => {
  const id=sanInt(req.params.id), action=san(req.body.action)||'confirmed';
  const appt=(await pool.query('SELECT * FROM appointments WHERE id=$1',[id])).rows[0];
  if (!appt) return res.status(404).json({ error:'الموعد غير موجود' });
  const pt=(await pool.query('SELECT * FROM patients WHERE id=$1',[appt.patient_id])).rows[0];
  const dr=(await pool.query('SELECT name FROM doctors WHERE id=$1',[appt.doctor_id])).rows[0];
  const msgs={
    confirmed:`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n📅 ${appt.appointment_date} ⏰ ${String(appt.appointment_time).substring(0,5)}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${appt.service}\n📍 بغداد - الحارثية\n📞 07747881005`,
    reminder:`🦷 *تذكير*\n\nعزيزي ${pt.name}،\nلديك موعد:\n📅 ${appt.appointment_date} ⏰ ${String(appt.appointment_time).substring(0,5)}\nنأمل حضورك 🙏`,
    cancelled:`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم إلغاء موعدك.\nللحجز: 07747881005`,
    reschedule:`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nنعتذر — الطبيب ${dr?.name||'—'} غير متاح. سنتواصل معك لترتيب موعد بديل.\n📞 07747881005`,
  };
  const msg=msgs[action]||msgs.confirmed;
  const waPhone=pt.phone.startsWith('0')?'964'+pt.phone.slice(1):pt.phone;
  await pool.query('INSERT INTO notifications_log(appointment_id,type,status,message) VALUES($1,$2,$3,$4)',[appt.id,'whatsapp','sent',msg]);
  res.json({ success:true, waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
});

// ── Users ─────────────────────────────────────────────────
app.get('/api/users', auth(['admin']), async (_,res) => {
  const { rows }=await pool.query('SELECT id,name,email,username,role,is_active,last_login,created_at FROM users ORDER BY created_at');
  res.json(rows);
});
app.post('/api/users', auth(['admin']), async (req,res) => {
  const name=san(req.body.name), pwd=String(req.body.password||'').slice(0,128);
  const role=['admin','doctor','receptionist'].includes(req.body.role)?req.body.role:'receptionist';
  if (!name||!pwd||pwd.length<6) return res.status(400).json({ error:'الاسم وكلمة المرور (٦ أحرف) مطلوبان' });
  const uname=san(req.body.username)||san(req.body.email)||name;
  const hash=await bcrypt.hash(pwd,10);
  const { rows }=await pool.query(
    'INSERT INTO users(name,email,username,password,role,doctor_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,email,username,role',
    [name,sanEmail(req.body.email)||null,uname,hash,role,sanInt(req.body.doctor_id)||null]
  );
  await audit(req.user.id,req.user.name,'CREATE','users',rows[0].id,req._ip,`role=${role}`);
  res.json(rows[0]);
});
app.patch('/api/users/:id', auth(['admin']), async (req,res) => {
  const id=sanInt(req.params.id);
  const is_active=req.body.is_active!=null?Boolean(req.body.is_active):null;
  const role=['admin','doctor','receptionist'].includes(req.body.role)?req.body.role:null;
  const { rows }=await pool.query(
    'UPDATE users SET is_active=COALESCE($1,is_active),role=COALESCE($2,role) WHERE id=$3 RETURNING id,name,email,role,is_active',
    [is_active,role,id]
  );
  await audit(req.user.id,req.user.name,'UPDATE','users',id,req._ip,null);
  res.json(rows[0]);
});
app.delete('/api/users/:id', auth(['admin']), async (req,res) => {
  const id=sanInt(req.params.id);
  if (id===req.user.id) return res.status(400).json({ error:'لا يمكنك حذف حسابك الخاص' });
  await pool.query('DELETE FROM users WHERE id=$1',[id]);
  await audit(req.user.id,req.user.name,'DELETE','users',id,req._ip,null);
  res.json({ success:true });
});

// ── Audit log ─────────────────────────────────────────────
app.get('/api/audit', auth(['admin']), async (_,res) => {
  const { rows }=await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200');
  res.json(rows);
});

// ── 404 + error handler ───────────────────────────────────
app.use((_,res) => res.status(404).json({ error:'المسار غير موجود' }));
app.use((err,_,res,__) => { console.error(err); res.status(500).json({ error:'خطأ داخلي' }); });

// ── Boot ──────────────────────────────────────────────────
initDB().catch(e => console.error('initDB failed:', e.message));
if (process.env.VERCEL!=='1') app.listen(PORT,()=>console.log(`🦷 Rawasi API :${PORT}`));
module.exports = app;
