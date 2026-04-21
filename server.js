/*
  🦷 رواسي لطب الأسنان — النسخة الكاملة v5
  Vercel + Neon + Cloudinary
  Admin: rexlmk / mhmd@123
*/
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { Pool }   = require('pg');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3001;

// ══════════════════════════════════════════════════════════
//  SECURITY — Helmet (headers hardened)
// ══════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", "https://upload.cloudinary.com"],
      styleSrc:       ["'self'", "'unsafe-inline'"],
      imgSrc:         ["'self'", "data:", "https://res.cloudinary.com"],
      connectSrc:     ["'self'", "https://api.cloudinary.com", "https://wa.me"],
      frameSrc:       ["'none'"],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts:                   { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy:         { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy:      false,
  crossOriginEmbedderPolicy: false,
}));

// ══════════════════════════════════════════════════════════
//  CORS — restrict to known origins only
// ══════════════════════════════════════════════════════════
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server (no origin) and listed origins
    if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      return cb(null, true);
    }
    cb(new Error('Not allowed by CORS'));
  },
  methods:          ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders:   ['Content-Type', 'Authorization'],
  credentials:      true,
  maxAge:           600,
}));

// ══════════════════════════════════════════════════════════
//  RATE LIMITER (in-memory, Vercel-safe)
// ══════════════════════════════════════════════════════════
const rateLimitStore = new Map();
function rateLimit({ windowMs = 60_000, max = 60, message = 'Too many requests' } = {}) {
  return (req, res, next) => {
    const key  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || 'unknown';
    const now  = Date.now();
    const rec  = rateLimitStore.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + windowMs; }
    rec.count++;
    rateLimitStore.set(key, rec);
    res.setHeader('X-RateLimit-Limit',     max);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - rec.count));
    if (rec.count > max) return res.status(429).json({ error: message });
    next();
  };
}
// Strict limiter for auth endpoints
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 20, message: 'محاولات كثيرة، انتظر 15 دقيقة' });
// General API limiter
const apiLimiter  = rateLimit({ windowMs: 60_000, max: 120 });

app.use('/api/', apiLimiter);

// ══════════════════════════════════════════════════════════
//  BODY PARSER — tight limits
// ══════════════════════════════════════════════════════════
app.use(express.json({ limit: '2mb' }));

// ══════════════════════════════════════════════════════════
//  INPUT SANITIZER — strip NUL bytes & trim strings
// ══════════════════════════════════════════════════════════
function sanitize(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  for (const k of Object.keys(obj)) {
    if (typeof obj[k] === 'string') {
      obj[k] = obj[k].replace(/\0/g, '').trim().substring(0, 2000);
    } else if (typeof obj[k] === 'object') {
      sanitize(obj[k]);
    }
  }
  return obj;
}
app.use((req, _res, next) => { sanitize(req.body); sanitize(req.query); next(); });

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
        username VARCHAR(100),
        email VARCHAR(150),
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'receptionist',
        doctor_id INTEGER,
        is_active BOOLEAN DEFAULT true,
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
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS patient_cases (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE SET NULL,
        title VARCHAR(200) NOT NULL,
        description TEXT,
        diagnosis TEXT,
        treatment_plan TEXT,
        status VARCHAR(30) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS case_sessions (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES patient_cases(id) ON DELETE CASCADE,
        appointment_id INTEGER REFERENCES appointments(id) ON DELETE SET NULL,
        session_date DATE NOT NULL,
        notes TEXT,
        procedure_done TEXT,
        next_session TEXT,
        cost NUMERIC(10,2),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS case_images (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES patient_cases(id) ON DELETE CASCADE,
        session_id INTEGER REFERENCES case_sessions(id) ON DELETE SET NULL,
        image_url TEXT NOT NULL,
        image_type VARCHAR(20) DEFAULT 'photo',
        caption TEXT,
        uploaded_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS notifications_log (
        id SERIAL PRIMARY KEY,
        appointment_id INTEGER REFERENCES appointments(id) ON DELETE CASCADE,
        type VARCHAR(20),
        status VARCHAR(20),
        message TEXT,
        sent_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS doctor_day_status (
        id SERIAL PRIMARY KEY,
        doctor_id INTEGER REFERENCES doctors(id) ON DELETE CASCADE,
        status_date DATE NOT NULL,
        available BOOLEAN NOT NULL DEFAULT true,
        note VARCHAR(300),
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(doctor_id, status_date)
      );
    `);

    // seed doctors
    const { rowCount: dc } = await c.query('SELECT id FROM doctors LIMIT 1');
    if (!dc) {
      await c.query(`
        INSERT INTO doctors (name,specialty,color,start_time,end_time) VALUES
        ('د. رواسي رعد العامري','تقويم الأسنان',           '#3C2A98','09:00','18:00'),
        ('د. علي العزال',       'حشوات جذور وابتسامات',   '#7B6DD4','09:00','18:00'),
        ('د. عبدالله جمال',     'طب الأسنان العام',        '#534AB7','10:00','17:00'),
        ('د. نهلة العبيدي',     'تجميل الأسنان',           '#9D8FE8','09:00','16:00')
      `);
      const { rows: docs } = await c.query('SELECT id FROM doctors');
      for (const d of docs) {
        for (let day = 0; day <= 5; day++) {
          await c.query(
            'INSERT INTO doctor_available_days (doctor_id,day_of_week,start_time,end_time) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
            [d.id, day, '09:00', '18:00']
          );
        }
      }
    }

    // seed admin — NEW credentials: rexlmk / mhmd@123
    const { rowCount: uc } = await c.query("SELECT id FROM users WHERE username='rexlmk' LIMIT 1");
    if (!uc) {
      const hash = await bcrypt.hash('mhmd@123', 10);
      await c.query(
        `INSERT INTO users (name,email,username,password,role) VALUES ('المديرة','admin@rawasi.iq','rexlmk',$1,'admin')
         ON CONFLICT DO NOTHING`,
        [hash]
      );
      // deactivate old admin if exists
      await c.query(`UPDATE users SET is_active=false WHERE username='admin' AND username!='rexlmk'`);
    }
    console.log('✅ DB ready');
  } catch(e) { console.error('initDB:', e.message); }
  finally { c.release(); }
}

// ══════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ══════════════════════════════════════════════════════════
function auth(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح' });
    try {
      const p = jwt.verify(token, process.env.JWT_SECRET || 'rawasi-secret-2025');
      if (roles.length && !roles.includes(p.role))
        return res.status(403).json({ error: 'ليس لديك صلاحية' });
      req.user = p;
      next();
    } catch { res.status(401).json({ error: 'انتهت الجلسة' }); }
  };
}

// ══════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════

app.get('/api/health', async (_,res) => {
  try { await pool.query('SELECT 1'); res.json({ status:'ok', db:'connected' }); }
  catch(e) { res.status(500).json({ status:'error', db:e.message }); }
});

// ── Auth ────────────────────────────────────────────────
app.post('/api/auth/login', authLimiter, async (req,res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ error:'أدخل اسم المستخدم وكلمة المرور' });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE (email=$1 OR username=$1) AND is_active=true', [email]
    );
    if (!rows.length) return res.status(401).json({ error:'الحساب غير موجود' });
    const user = rows[0];
    const ok = user.password.startsWith('$2')
      ? await bcrypt.compare(password, user.password)
      : password === user.password;
    if (!ok) return res.status(401).json({ error:'كلمة المرور خطأ' });
    const token = jwt.sign(
      { id:user.id, name:user.name, email:user.email, role:user.role, doctor_id:user.doctor_id },
      process.env.JWT_SECRET||'rawasi-secret-2025',
      { expiresIn:'12h' }
    );
    res.json({ token, user:{ id:user.id, name:user.name, role:user.role, doctor_id:user.doctor_id } });
  } catch(e) { console.error(e); res.status(500).json({ error:'خطأ في السيرفر' }); }
});

app.get('/api/auth/me', auth(), (req,res) => res.json(req.user));

// ── PUBLIC: Doctors list (for booking page) ─────────────
app.get('/api/public/doctors', async (_,res) => {
  try {
    const { rows } = await pool.query('SELECT id,name,specialty,color,start_time,end_time FROM doctors WHERE is_active=true ORDER BY name');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PUBLIC: Slots (for booking page) ───────────────────
app.get('/api/public/slots', async (req,res) => {
  const { doctor_id, date } = req.query;
  if (!doctor_id||!date) return res.status(400).json({ error:'doctor_id و date مطلوبان' });
  try {
    const dr = (await pool.query('SELECT * FROM doctors WHERE id=$1',[doctor_id])).rows[0];
    if (!dr) return res.status(404).json({ error:'الطبيب غير موجود' });

    // Check doctor's manual day status override
    const dayStatusRow = await pool.query(
      'SELECT available, note FROM doctor_day_status WHERE doctor_id=$1 AND status_date=$2',
      [doctor_id, date]
    );
    const doctorUnavailable = dayStatusRow.rowCount > 0 && !dayStatusRow.rows[0].available;
    const unavailableNote   = doctorUnavailable ? (dayStatusRow.rows[0].note || 'الطبيب غير متوفر') : null;

    // Check weekly schedule
    const dayOfWeek = new Date(date).getDay();
    const dayRow = await pool.query(
      'SELECT * FROM doctor_available_days WHERE doctor_id=$1 AND day_of_week=$2',
      [doctor_id, dayOfWeek]
    );
    // If no weekly schedule AND no manual override allowing it → truly no slots
    if (!dayRow.rowCount && !doctorUnavailable) return res.json({ unavailable:true, doctorUnavailable:false, slots:[] });

    const sched = dayRow.rows[0] || { start_time: dr.start_time||'09:00', end_time: dr.end_time||'18:00' };
    const booked = await pool.query(
      `SELECT TO_CHAR(appointment_time,'HH24:MI') as t FROM appointments
       WHERE doctor_id=$1 AND appointment_date=$2 AND status!='cancelled'`,
      [doctor_id,date]
    );
    const bookedTimes = booked.rows.map(r=>r.t);
    const slots=[];
    const [sh,sm] = sched.start_time.split(':').map(Number);
    const [eh,em] = sched.end_time.split(':').map(Number);
    let cur = sh*60+sm;
    const end = eh*60+em;
    while (cur<end) {
      const h=String(Math.floor(cur/60)).padStart(2,'0');
      const m=String(cur%60).padStart(2,'0');
      slots.push({ time:`${h}:${m}`, available:!bookedTimes.includes(`${h}:${m}`) });
      cur+=dr.slot_duration||30;
    }
    // Return slots regardless — but flag doctorUnavailable so frontend can warn
    res.json({ unavailable:false, doctorUnavailable, unavailableNote, slots });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PUBLIC: Book appointment (self-booking) ─────────────
app.post('/api/public/book', async (req,res) => {
  const { name, phone, service, doctor_id, appointment_date, appointment_time, notes, age, gender } = req.body;
  if (!name||!phone||!service||!doctor_id||!appointment_date||!appointment_time)
    return res.status(400).json({ error:'يرجى تعبئة جميع الحقول المطلوبة' });
  try {
    // Find or create patient
    let pt = (await pool.query('SELECT * FROM patients WHERE phone=$1',[phone])).rows[0];
    if (!pt) {
      const ins = await pool.query(
        'INSERT INTO patients (name,phone,age,gender,notes) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [name,phone,age||null,gender||null,notes||null]
      );
      pt = ins.rows[0];
    }
    // Check conflict
    const conflict = await pool.query(
      `SELECT id FROM appointments WHERE doctor_id=$1 AND appointment_date=$2
       AND appointment_time=$3 AND status!='cancelled'`,
      [doctor_id,appointment_date,appointment_time]
    );
    if (conflict.rowCount) return res.status(409).json({ error:'هذا الوقت محجوز مسبقاً، يرجى اختيار وقت آخر' });
    const dr = (await pool.query('SELECT name FROM doctors WHERE id=$1',[doctor_id])).rows[0];
    const { rows } = await pool.query(
      `INSERT INTO appointments (patient_id,doctor_id,service,appointment_date,appointment_time,notes,status)
       VALUES ($1,$2,$3,$4,$5,$6,'pending') RETURNING *`,
      [pt.id,doctor_id,service,appointment_date,appointment_time,notes||null]
    );
    const msg = `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم استلام طلب حجزك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${service}\n\nسيتم التأكيد قريباً.\n📍 بغداد - الحارثية - مقابل مول بغداد\n📞 07747881005`;
    const waPhone = pt.phone.startsWith('0') ? '964'+pt.phone.slice(1) : pt.phone;
    res.json({ success:true, appointment:rows[0], waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
  } catch(e) { console.error(e); res.status(500).json({ error:'خطأ في السيرفر' }); }
});

// ── Doctors ─────────────────────────────────────────────
app.get('/api/doctors', auth(), async (_,res) => {
  const { rows } = await pool.query('SELECT * FROM doctors WHERE is_active=true ORDER BY name');
  res.json(rows);
});

app.post('/api/doctors', auth(['admin']), async (req,res) => {
  const { name,specialty,phone,email,color,start_time,end_time,slot_duration } = req.body;
  if (!name) return res.status(400).json({ error:'الاسم مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO doctors (name,specialty,phone,email,color,start_time,end_time,slot_duration)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [name,specialty,phone,email,color||'#3C2A98',start_time||'09:00',end_time||'18:00',slot_duration||30]
  );
  res.json(rows[0]);
});

// ── DELETE Doctor (admin only) ───────────────────────────
app.delete('/api/doctors/:id', auth(['admin']), async (req,res) => {
  // Soft delete
  await pool.query('UPDATE doctors SET is_active=false WHERE id=$1',[req.params.id]);
  res.json({ success:true });
});

// ── Doctor Available Days ────────────────────────────────
app.get('/api/doctors/:id/schedule', auth(), async (req,res) => {
  const { rows } = await pool.query(
    'SELECT * FROM doctor_available_days WHERE doctor_id=$1 ORDER BY day_of_week',
    [req.params.id]
  );
  res.json(rows);
});

app.put('/api/doctors/:id/schedule', auth(['admin','doctor']), async (req,res) => {
  const docId = +req.params.id;
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'يمكنك تعديل جدولك فقط' });
  const { days } = req.body;
  await pool.query('DELETE FROM doctor_available_days WHERE doctor_id=$1', [docId]);
  for (const d of days.filter(x=>x.active)) {
    await pool.query(
      'INSERT INTO doctor_available_days (doctor_id,day_of_week,start_time,end_time) VALUES ($1,$2,$3,$4)',
      [docId, d.day_of_week, d.start_time||'09:00', d.end_time||'18:00']
    );
  }
  res.json({ success:true });
});

// ── Doctor Day Status (availability toggle per date) ─────
// GET: doctor fetches their own status for a date range (current month)
app.get('/api/doctors/:id/day-status', auth(['admin','doctor','receptionist']), async (req,res) => {
  const docId = +req.params.id;
  const { from, to } = req.query;
  if (!from || !to) return res.status(400).json({ error:'from و to مطلوبان' });
  const { rows } = await pool.query(
    'SELECT status_date, available, note FROM doctor_day_status WHERE doctor_id=$1 AND status_date BETWEEN $2 AND $3 ORDER BY status_date',
    [docId, from, to]
  );
  res.json(rows);
});

// PUT: doctor sets their availability for a specific date
app.put('/api/doctors/:id/day-status', auth(['admin','doctor']), async (req,res) => {
  const docId = +req.params.id;
  if (req.user.role === 'doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'يمكنك تعديل جدولك فقط' });
  const { status_date, available, note } = req.body;
  if (!status_date || available === undefined)
    return res.status(400).json({ error:'status_date و available مطلوبان' });
  const { rows } = await pool.query(
    `INSERT INTO doctor_day_status (doctor_id, status_date, available, note, updated_at)
     VALUES ($1,$2,$3,$4,NOW())
     ON CONFLICT (doctor_id, status_date)
     DO UPDATE SET available=EXCLUDED.available, note=EXCLUDED.note, updated_at=NOW()
     RETURNING *`,
    [docId, status_date, available, note||null]
  );
  res.json(rows[0]);
});

// ── Doctor Profile (stats) ───────────────────────────────
app.get('/api/doctors/:id/profile', auth(['admin','doctor']), async (req,res) => {
  const docId = +req.params.id;
  if (req.user.role==='doctor' && req.user.doctor_id !== docId)
    return res.status(403).json({ error:'غير مصرح' });
  const [dr, totalAppts, completedAppts, totalCases, totalPatients, schedule] = await Promise.all([
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
    stats: {
      total_appointments: +totalAppts.rows[0].count,
      completed_appointments: +completedAppts.rows[0].count,
      total_cases: +totalCases.rows[0].count,
      total_patients: +totalPatients.rows[0].count,
    },
    schedule: schedule.rows,
  });
});

// ── Patients ─────────────────────────────────────────────
app.get('/api/patients', auth(), async (req,res) => {
  const { search } = req.query;
  let q = 'SELECT * FROM patients';
  const p = [];
  if (search) { q+=' WHERE name ILIKE $1 OR phone ILIKE $1'; p.push(`%${search}%`); }
  q+=' ORDER BY created_at DESC LIMIT 200';
  const { rows } = await pool.query(q,p);
  res.json(rows);
});

app.post('/api/patients', auth(['admin','receptionist']), async (req,res) => {
  const { name,phone,email,age,gender,notes } = req.body;
  if (!name||!phone) return res.status(400).json({ error:'الاسم والهاتف مطلوبان' });
  const ex = await pool.query('SELECT * FROM patients WHERE phone=$1',[phone]);
  if (ex.rowCount) return res.json(ex.rows[0]);
  const { rows } = await pool.query(
    'INSERT INTO patients (name,phone,email,age,gender,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [name,phone,email||null,age||null,gender||null,notes||null]
  );
  res.json(rows[0]);
});

// ── Patient Full Page (doctor/admin only) ────────────────
app.get('/api/patients/:id', auth(), async (req,res) => {
  // Receptionist can see basic info, doctor/admin see full with cases
  const { rows } = await pool.query('SELECT * FROM patients WHERE id=$1',[req.params.id]);
  if (!rows.length) return res.status(404).json({ error:'غير موجود' });
  const [appts, cases] = await Promise.all([
    pool.query(
      `SELECT a.*, d.name as doctor_name FROM appointments a
       LEFT JOIN doctors d ON a.doctor_id=d.id
       WHERE a.patient_id=$1 ORDER BY a.appointment_date DESC`,
      [req.params.id]
    ),
    pool.query(
      `SELECT pc.*, d.name as doctor_name,
        (SELECT COUNT(*) FROM case_sessions WHERE case_id=pc.id) as session_count
       FROM patient_cases pc LEFT JOIN doctors d ON pc.doctor_id=d.id
       WHERE pc.patient_id=$1 ORDER BY pc.created_at DESC`,
      [req.params.id]
    ),
  ]);
  // For doctor/admin: include full cases; for receptionist: no cases
  const canSeeCases = ['admin','doctor'].includes(req.user.role);
  res.json({ ...rows[0], appointments:appts.rows, cases: canSeeCases ? cases.rows : [] });
});

// ── Appointments ─────────────────────────────────────────
app.get('/api/appointments', auth(), async (req,res) => {
  const { date,doctor_id,status,from,to } = req.query;
  let q = `
    SELECT a.*, p.name as patient_name, p.phone as patient_phone,
           d.name as doctor_name, d.color as doctor_color
    FROM appointments a
    LEFT JOIN patients p ON a.patient_id=p.id
    LEFT JOIN doctors  d ON a.doctor_id=d.id
    WHERE 1=1
  `;
  const params=[]; let i=1;
  if (date)      { q+=` AND a.appointment_date=$${i++}`; params.push(date); }
  if (from)      { q+=` AND a.appointment_date>=$${i++}`; params.push(from); }
  if (to)        { q+=` AND a.appointment_date<=$${i++}`; params.push(to); }
  if (doctor_id) { q+=` AND a.doctor_id=$${i++}`; params.push(doctor_id); }
  if (status)    { q+=` AND a.status=$${i++}`; params.push(status); }
  if (req.user.role==='doctor' && req.user.doctor_id) {
    q+=` AND a.doctor_id=$${i++}`; params.push(req.user.doctor_id);
  }
  q+=' ORDER BY a.appointment_date, a.appointment_time';
  const { rows } = await pool.query(q,params);
  res.json(rows);
});

app.post('/api/appointments', auth(['admin','receptionist']), async (req,res) => {
  const { patient_id,doctor_id,service,appointment_date,appointment_time,notes } = req.body;
  if (!patient_id||!doctor_id||!service||!appointment_date||!appointment_time)
    return res.status(400).json({ error:'جميع الحقول مطلوبة' });
  const conflict = await pool.query(
    `SELECT id FROM appointments WHERE doctor_id=$1 AND appointment_date=$2
     AND appointment_time=$3 AND status!='cancelled'`,
    [doctor_id,appointment_date,appointment_time]
  );
  if (conflict.rowCount) return res.status(409).json({ error:'هذا الوقت محجوز مسبقاً' });
  const { rows } = await pool.query(
    `INSERT INTO appointments (patient_id,doctor_id,service,appointment_date,appointment_time,notes,created_by,status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'pending') RETURNING *`,
    [patient_id,doctor_id,service,appointment_date,appointment_time,notes||null,req.user.id]
  );
  const pt = (await pool.query('SELECT * FROM patients WHERE id=$1',[patient_id])).rows[0];
  const dr = (await pool.query('SELECT name FROM doctors WHERE id=$1',[doctor_id])).rows[0];
  const msg = `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${service}\n\n📍 بغداد - الحارثية - مقابل مول بغداد\n📞 07747881005`;
  const waPhone = pt.phone.startsWith('0') ? '964'+pt.phone.slice(1) : pt.phone;
  res.json({ ...rows[0], waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
});

app.patch('/api/appointments/:id', auth(['admin','receptionist']), async (req,res) => {
  const { status,notes,appointment_date,appointment_time } = req.body;
  const { rows } = await pool.query(
    `UPDATE appointments SET status=COALESCE($1,status), notes=COALESCE($2,notes),
     appointment_date=COALESCE($3,appointment_date), appointment_time=COALESCE($4,appointment_time),
     updated_at=NOW() WHERE id=$5 RETURNING *`,
    [status||null,notes||null,appointment_date||null,appointment_time||null,req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error:'الموعد غير موجود' });
  res.json(rows[0]);
});

app.delete('/api/appointments/:id', auth(['admin']), async (req,res) => {
  await pool.query('DELETE FROM appointments WHERE id=$1',[req.params.id]);
  res.json({ success:true });
});

// ── Slots ─────────────────────────────────────────────────
app.get('/api/slots', auth(), async (req,res) => {
  const { doctor_id,date } = req.query;
  if (!doctor_id||!date) return res.status(400).json({ error:'doctor_id و date مطلوبان' });
  const dr = (await pool.query('SELECT * FROM doctors WHERE id=$1',[doctor_id])).rows[0];
  if (!dr) return res.status(404).json({ error:'الطبيب غير موجود' });

  const dayStatusRow = await pool.query(
    'SELECT available, note FROM doctor_day_status WHERE doctor_id=$1 AND status_date=$2',
    [doctor_id, date]
  );
  const doctorUnavailable = dayStatusRow.rowCount > 0 && !dayStatusRow.rows[0].available;
  const unavailableNote   = doctorUnavailable ? (dayStatusRow.rows[0].note || 'الطبيب غير متوفر') : null;

  const dayOfWeek = new Date(date).getDay();
  const dayRow = await pool.query(
    'SELECT * FROM doctor_available_days WHERE doctor_id=$1 AND day_of_week=$2',
    [doctor_id, dayOfWeek]
  );
  if (!dayRow.rowCount && !doctorUnavailable) return res.json({ unavailable:true, doctorUnavailable:false, slots:[] });
  const sched = dayRow.rows[0] || { start_time: dr.start_time||'09:00', end_time: dr.end_time||'18:00' };
  const booked = await pool.query(
    `SELECT TO_CHAR(appointment_time,'HH24:MI') as t FROM appointments
     WHERE doctor_id=$1 AND appointment_date=$2 AND status!='cancelled'`,
    [doctor_id,date]
  );
  const bookedTimes = booked.rows.map(r=>r.t);
  const slots=[];
  const [sh,sm] = sched.start_time.split(':').map(Number);
  const [eh,em] = sched.end_time.split(':').map(Number);
  let cur = sh*60+sm;
  const end = eh*60+em;
  while (cur<end) {
    const h=String(Math.floor(cur/60)).padStart(2,'0');
    const m=String(cur%60).padStart(2,'0');
    slots.push({ time:`${h}:${m}`, available:!bookedTimes.includes(`${h}:${m}`) });
    cur+=dr.slot_duration||30;
  }
  res.json({ unavailable:false, doctorUnavailable, unavailableNote, slots });
});

// ── Patient Cases ─────────────────────────────────────────
app.get('/api/cases', auth(), async (req,res) => {
  const { patient_id,doctor_id } = req.query;
  let q=`SELECT pc.*, d.name as doctor_name, p.name as patient_name,
    (SELECT COUNT(*) FROM case_sessions WHERE case_id=pc.id) as session_count
   FROM patient_cases pc
   LEFT JOIN doctors d ON pc.doctor_id=d.id
   LEFT JOIN patients p ON pc.patient_id=p.id WHERE 1=1`;
  const params=[]; let i=1;
  if (patient_id) { q+=` AND pc.patient_id=$${i++}`; params.push(patient_id); }
  if (doctor_id)  { q+=` AND pc.doctor_id=$${i++}`; params.push(doctor_id); }
  if (req.user.role==='doctor' && req.user.doctor_id) {
    q+=` AND pc.doctor_id=$${i++}`; params.push(req.user.doctor_id);
  }
  q+=' ORDER BY pc.created_at DESC';
  const { rows } = await pool.query(q,params);
  res.json(rows);
});

app.post('/api/cases', auth(['admin','doctor','receptionist']), async (req,res) => {
  const { patient_id,doctor_id,title,description,diagnosis,treatment_plan } = req.body;
  if (!patient_id||!title) return res.status(400).json({ error:'المريض والعنوان مطلوبان' });
  const { rows } = await pool.query(
    `INSERT INTO patient_cases (patient_id,doctor_id,title,description,diagnosis,treatment_plan)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [patient_id,doctor_id||req.user.doctor_id||null,title,description||null,diagnosis||null,treatment_plan||null]
  );
  res.json(rows[0]);
});

app.get('/api/cases/:id', auth(['admin','doctor']), async (req,res) => {
  const { rows } = await pool.query(
    `SELECT pc.*, d.name as doctor_name, p.name as patient_name, p.phone as patient_phone
     FROM patient_cases pc
     LEFT JOIN doctors d ON pc.doctor_id=d.id
     LEFT JOIN patients p ON pc.patient_id=p.id
     WHERE pc.id=$1`, [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error:'الحالة غير موجودة' });
  const [sessions,images] = await Promise.all([
    pool.query('SELECT * FROM case_sessions WHERE case_id=$1 ORDER BY session_date DESC',[req.params.id]),
    pool.query('SELECT * FROM case_images WHERE case_id=$1 ORDER BY uploaded_at DESC',[req.params.id]),
  ]);
  res.json({ ...rows[0], sessions:sessions.rows, images:images.rows });
});

app.patch('/api/cases/:id', auth(['admin','doctor']), async (req,res) => {
  const { title,description,diagnosis,treatment_plan,status } = req.body;
  const { rows } = await pool.query(
    `UPDATE patient_cases SET
     title=COALESCE($1,title), description=COALESCE($2,description),
     diagnosis=COALESCE($3,diagnosis), treatment_plan=COALESCE($4,treatment_plan),
     status=COALESCE($5,status), updated_at=NOW()
     WHERE id=$6 RETURNING *`,
    [title||null,description||null,diagnosis||null,treatment_plan||null,status||null,req.params.id]
  );
  res.json(rows[0]);
});

// ── Case Sessions ─────────────────────────────────────────
app.post('/api/cases/:id/sessions', auth(['admin','doctor']), async (req,res) => {
  const { session_date,notes,procedure_done,next_session,cost,appointment_id } = req.body;
  if (!session_date) return res.status(400).json({ error:'تاريخ الجلسة مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO case_sessions (case_id,appointment_id,session_date,notes,procedure_done,next_session,cost)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [req.params.id,appointment_id||null,session_date,notes||null,procedure_done||null,next_session||null,cost||null]
  );
  res.json(rows[0]);
});

app.patch('/api/sessions/:id', auth(['admin','doctor']), async (req,res) => {
  const { notes,procedure_done,next_session,cost } = req.body;
  const { rows } = await pool.query(
    `UPDATE case_sessions SET notes=COALESCE($1,notes), procedure_done=COALESCE($2,procedure_done),
     next_session=COALESCE($3,next_session), cost=COALESCE($4,cost) WHERE id=$5 RETURNING *`,
    [notes||null,procedure_done||null,next_session||null,cost||null,req.params.id]
  );
  res.json(rows[0]);
});

// ── Case Images (Cloudinary) ──────────────────────────────
app.post('/api/cases/:id/images', auth(['admin','doctor']), async (req,res) => {
  const { image_url,image_type,caption,session_id } = req.body;
  if (!image_url) return res.status(400).json({ error:'رابط الصورة مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO case_images (case_id,session_id,image_url,image_type,caption)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [req.params.id,session_id||null,image_url,image_type||'photo',caption||null]
  );
  res.json(rows[0]);
});

app.delete('/api/images/:id', auth(['admin','doctor']), async (req,res) => {
  await pool.query('DELETE FROM case_images WHERE id=$1',[req.params.id]);
  res.json({ success:true });
});

// ── Cloudinary Signature ─────────────────────────────────
app.get('/api/cloudinary/signature', auth(['admin','doctor']), (req,res) => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey    = process.env.CLOUDINARY_API_KEY;
  const uploadPreset = process.env.CLOUDINARY_UPLOAD_PRESET || 'rawasi_clinic';
  if (!cloudName||!apiKey)
    return res.status(500).json({ error:'Cloudinary غير مضبوط في البيئة' });
  res.json({ cloudName, apiKey, uploadPreset });
});

// ── Reports ───────────────────────────────────────────────
app.get('/api/reports/summary', auth(['admin','receptionist']), async (req,res) => {
  let { from,to } = req.query;
  if (!from||!to) {
    const d=new Date();
    from=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-01`;
    to=d.toISOString().split('T')[0];
  }
  const [total,today,pending,completed,byDoctor,byService] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date=CURRENT_DATE`),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='pending' AND appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='completed' AND appointment_date BETWEEN $1 AND $2`,[from,to]),
    pool.query(`SELECT d.name, COUNT(a.id) as count FROM appointments a LEFT JOIN doctors d ON a.doctor_id=d.id WHERE a.appointment_date BETWEEN $1 AND $2 GROUP BY d.name ORDER BY count DESC`,[from,to]),
    pool.query(`SELECT service, COUNT(*) as count FROM appointments WHERE appointment_date BETWEEN $1 AND $2 GROUP BY service ORDER BY count DESC LIMIT 8`,[from,to]),
  ]);
  res.json({
    total:+total.rows[0].count, today:+today.rows[0].count,
    pending:+pending.rows[0].count, completed:+completed.rows[0].count,
    byDoctor:byDoctor.rows, byService:byService.rows,
  });
});

// ── Notify WhatsApp ───────────────────────────────────────
app.post('/api/appointments/:id/notify', auth(['admin','receptionist']), async (req,res) => {
  const { action='confirmed' } = req.body;
  const appt=(await pool.query('SELECT * FROM appointments WHERE id=$1',[req.params.id])).rows[0];
  if (!appt) return res.status(404).json({ error:'الموعد غير موجود' });
  const pt=(await pool.query('SELECT * FROM patients WHERE id=$1',[appt.patient_id])).rows[0];
  const dr=(await pool.query('SELECT name FROM doctors WHERE id=$1',[appt.doctor_id])).rows[0];
  const msgs={
    confirmed:`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n\n📅 ${appt.appointment_date}\n⏰ ${String(appt.appointment_time).substring(0,5)}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${appt.service}\n\n📍 بغداد - الحارثية - مقابل مول بغداد\n📞 07747881005`,
    reminder:`🦷 *تذكير*\n\nعزيزي ${pt.name}،\nلديك موعد:\n📅 ${appt.appointment_date} ⏰ ${String(appt.appointment_time).substring(0,5)}\n👨‍⚕️ ${dr?.name||'—'}\nنأمل حضورك 🙏`,
    cancelled:`🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم إلغاء موعدك.\nللحجز: 07747881005`,
  };
  const msg=msgs[action]||msgs.confirmed;
  const waPhone=pt.phone.startsWith('0')?'964'+pt.phone.slice(1):pt.phone;
  await pool.query('INSERT INTO notifications_log (appointment_id,type,status,message) VALUES ($1,$2,$3,$4)',
    [appt.id,'whatsapp','sent',msg]);
  res.json({ success:true, waUrl:`https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}` });
});

// ── Users ─────────────────────────────────────────────────
app.get('/api/users', auth(['admin']), async (_,res) => {
  const { rows }=await pool.query('SELECT id,name,email,username,role,is_active,created_at FROM users ORDER BY created_at');
  res.json(rows);
});

app.post('/api/users', auth(['admin']), async (req,res) => {
  const { name,email,username,password,role,doctor_id }=req.body;
  if (!name||!password) return res.status(400).json({ error:'الاسم وكلمة المرور مطلوبان' });
  const hash=await bcrypt.hash(password,10);
  const uname = username || email;
  const { rows }=await pool.query(
    'INSERT INTO users (name,email,username,password,role,doctor_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id,name,email,username,role',
    [name,email||null,uname,hash,role||'receptionist',doctor_id||null]
  );
  res.json(rows[0]);
});

app.patch('/api/users/:id', auth(['admin']), async (req,res) => {
  const { is_active,role }=req.body;
  const { rows }=await pool.query(
    'UPDATE users SET is_active=COALESCE($1,is_active),role=COALESCE($2,role) WHERE id=$3 RETURNING id,name,email,role,is_active',
    [is_active??null,role||null,req.params.id]
  );
  res.json(rows[0]);
});

// ── DELETE User (admin only, cannot delete self) ─────────
app.delete('/api/users/:id', auth(['admin']), async (req,res) => {
  if (+req.params.id === req.user.id)
    return res.status(400).json({ error:'لا يمكنك حذف حسابك الخاص' });
  await pool.query('DELETE FROM users WHERE id=$1',[req.params.id]);
  res.json({ success:true });
});

// ── Start ─────────────────────────────────────────────────
initDB();
if (process.env.VERCEL!=='1') app.listen(PORT,()=>console.log(`🦷 Rawasi API :${PORT}`));
module.exports = app;
