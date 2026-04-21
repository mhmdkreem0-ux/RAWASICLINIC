/*
  🦷 رواسي لطب الأسنان
  Backend API — Vercel + Neon PostgreSQL
  النسخة الكاملة والمصححة
*/
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Database (Neon / Railway / أي PostgreSQL) ──────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,              // Vercel serverless: عدد صغير من الاتصالات
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// ── تهيئة الجداول ──────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
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

      CREATE TABLE IF NOT EXISTS notifications_log (
        id SERIAL PRIMARY KEY,
        appointment_id INTEGER REFERENCES appointments(id) ON DELETE CASCADE,
        type VARCHAR(20),
        status VARCHAR(20),
        message TEXT,
        sent_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // بيانات أولية — أطباء
    const { rowCount: dc } = await client.query('SELECT id FROM doctors LIMIT 1');
    if (!dc) {
      await client.query(`
        INSERT INTO doctors (name, specialty, color, start_time, end_time) VALUES
        ('د. رواسي رعد العامري', 'تقويم الأسنان',            '#3C2A98', '09:00', '18:00'),
        ('د. علي العزال',        'حشوات جذور وابتسامات',    '#7B6DD4', '09:00', '18:00'),
        ('د. عبدالله جمال',      'طب الأسنان العام',         '#534AB7', '10:00', '17:00'),
        ('د. نهلة العبيدي',      'تجميل الأسنان',            '#9D8FE8', '09:00', '16:00')
      `);
    }

    // بيانات أولية — المدير
    const { rowCount: uc } = await client.query('SELECT id FROM users LIMIT 1');
    if (!uc) {
      const hash = await bcrypt.hash('admin123', 10);
      await client.query(`
        INSERT INTO users (name, email, username, password, role)
        VALUES ('المدير', 'admin@rawasi.iq', 'admin', $1, 'admin')
      `, [hash]);
    }

    console.log('✅ DB ready');
  } catch (err) {
    console.error('DB init error:', err.message);
  } finally {
    client.release();
  }
}

// ── Auth Middleware ─────────────────────────────────────────
function auth(roles = []) {
  return (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'غير مصرح' });
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET || 'rawasi-secret-2025');
      if (roles.length && !roles.includes(payload.role))
        return res.status(403).json({ error: 'ليس لديك صلاحية' });
      req.user = payload;
      next();
    } catch {
      res.status(401).json({ error: 'انتهت الجلسة' });
    }
  };
}

// ══════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════

// ── Health ──────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', clinic: 'رواسي لطب الأسنان', db: 'connected' });
  } catch (e) {
    res.status(500).json({ status: 'error', db: e.message });
  }
});

// ── Auth ────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'أدخل البريد وكلمة المرور' });
  try {
    // يقبل email أو username
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE (email=$1 OR username=$1) AND is_active=true',
      [email]
    );
    if (!rows.length) return res.status(401).json({ error: 'الحساب غير موجود' });
    const user = rows[0];

    // يقبل كلمة مرور مشفرة أو نصية (للإعداد الأولي)
    let isValid = false;
    if (user.password.startsWith('$2')) {
      isValid = await bcrypt.compare(password, user.password);
    } else {
      isValid = (password === user.password);
    }
    if (!isValid) return res.status(401).json({ error: 'كلمة المرور خطأ' });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role, doctor_id: user.doctor_id },
      process.env.JWT_SECRET || 'rawasi-secret-2025',
      { expiresIn: '12h' }
    );
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'خطأ في السيرفر' });
  }
});

app.get('/api/auth/me', auth(), (req, res) => res.json(req.user));

// ── Doctors ─────────────────────────────────────────────
app.get('/api/doctors', auth(), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM doctors WHERE is_active=true ORDER BY name');
  res.json(rows);
});

app.post('/api/doctors', auth(['admin']), async (req, res) => {
  const { name, specialty, phone, email, color, start_time, end_time, slot_duration } = req.body;
  if (!name) return res.status(400).json({ error: 'الاسم مطلوب' });
  const { rows } = await pool.query(
    `INSERT INTO doctors (name,specialty,phone,email,color,start_time,end_time,slot_duration)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [name, specialty, phone, email, color||'#3C2A98', start_time||'09:00', end_time||'18:00', slot_duration||30]
  );
  res.json(rows[0]);
});

// ── Patients ─────────────────────────────────────────────
app.get('/api/patients', auth(), async (req, res) => {
  const { search } = req.query;
  let q = 'SELECT * FROM patients';
  const params = [];
  if (search) { q += ' WHERE name ILIKE $1 OR phone ILIKE $1'; params.push(`%${search}%`); }
  q += ' ORDER BY created_at DESC LIMIT 200';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/patients', auth(), async (req, res) => {
  const { name, phone, email, age, gender, notes } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'الاسم والهاتف مطلوبان' });
  // إذا الهاتف موجود، أرجع المريض الحالي
  const existing = await pool.query('SELECT * FROM patients WHERE phone=$1', [phone]);
  if (existing.rowCount) return res.json(existing.rows[0]);
  const { rows } = await pool.query(
    'INSERT INTO patients (name,phone,email,age,gender,notes) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [name, phone, email||null, age||null, gender||null, notes||null]
  );
  res.json(rows[0]);
});

app.get('/api/patients/:id', auth(), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM patients WHERE id=$1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'غير موجود' });
  const appts = await pool.query(
    `SELECT a.*, d.name as doctor_name FROM appointments a
     LEFT JOIN doctors d ON a.doctor_id=d.id
     WHERE a.patient_id=$1 ORDER BY a.appointment_date DESC`,
    [req.params.id]
  );
  res.json({ ...rows[0], appointments: appts.rows });
});

// ── Appointments ─────────────────────────────────────────
app.get('/api/appointments', auth(), async (req, res) => {
  const { date, doctor_id, status, from, to } = req.query;
  let q = `
    SELECT a.*, p.name as patient_name, p.phone as patient_phone,
           d.name as doctor_name, d.color as doctor_color
    FROM appointments a
    LEFT JOIN patients p ON a.patient_id=p.id
    LEFT JOIN doctors  d ON a.doctor_id=d.id
    WHERE 1=1
  `;
  const params = [];
  let i = 1;
  if (date)      { q += ` AND a.appointment_date=$${i++}`; params.push(date); }
  if (from)      { q += ` AND a.appointment_date>=$${i++}`; params.push(from); }
  if (to)        { q += ` AND a.appointment_date<=$${i++}`; params.push(to); }
  if (doctor_id) { q += ` AND a.doctor_id=$${i++}`; params.push(doctor_id); }
  if (status)    { q += ` AND a.status=$${i++}`; params.push(status); }

  // الطبيب يرى مواعيده فقط
  if (req.user.role === 'doctor' && req.user.doctor_id) {
    q += ` AND a.doctor_id=$${i++}`; params.push(req.user.doctor_id);
  }
  q += ' ORDER BY a.appointment_date, a.appointment_time';
  const { rows } = await pool.query(q, params);
  res.json(rows);
});

app.post('/api/appointments', auth(), async (req, res) => {
  const { patient_id, doctor_id, service, appointment_date, appointment_time, notes } = req.body;
  if (!patient_id || !doctor_id || !service || !appointment_date || !appointment_time)
    return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

  // التحقق من تعارض المواعيد
  const conflict = await pool.query(
    `SELECT id FROM appointments WHERE doctor_id=$1 AND appointment_date=$2
     AND appointment_time=$3 AND status!='cancelled'`,
    [doctor_id, appointment_date, appointment_time]
  );
  if (conflict.rowCount) return res.status(409).json({ error: 'هذا الوقت محجوز مسبقاً' });

  const { rows } = await pool.query(
    `INSERT INTO appointments
     (patient_id,doctor_id,service,appointment_date,appointment_time,notes,created_by,status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'pending') RETURNING *`,
    [patient_id, doctor_id, service, appointment_date, appointment_time, notes||null, req.user.id]
  );

  // واتساب — رابط مباشر (يُعاد للـ frontend)
  const pt = (await pool.query('SELECT * FROM patients WHERE id=$1', [patient_id])).rows[0];
  const dr = (await pool.query('SELECT name FROM doctors WHERE id=$1', [doctor_id])).rows[0];
  const msg = `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n\n📅 ${appointment_date}\n⏰ ${appointment_time}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${service}\n\n📍 بغداد - الحارثية - مقابل مول بغداد\n📞 07747881005`;
  const waPhone = pt.phone.startsWith('0') ? '964' + pt.phone.slice(1) : pt.phone;
  const waUrl = `https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}`;

  res.json({ ...rows[0], waUrl });
});

app.patch('/api/appointments/:id', auth(), async (req, res) => {
  const { status, notes, appointment_date, appointment_time } = req.body;
  const { rows } = await pool.query(
    `UPDATE appointments SET
       status=COALESCE($1,status),
       notes=COALESCE($2,notes),
       appointment_date=COALESCE($3,appointment_date),
       appointment_time=COALESCE($4,appointment_time),
       updated_at=NOW()
     WHERE id=$5 RETURNING *`,
    [status||null, notes||null, appointment_date||null, appointment_time||null, req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'الموعد غير موجود' });
  res.json(rows[0]);
});

app.delete('/api/appointments/:id', auth(['admin']), async (req, res) => {
  await pool.query('DELETE FROM appointments WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── Available Time Slots ──────────────────────────────────
app.get('/api/slots', auth(), async (req, res) => {
  const { doctor_id, date } = req.query;
  if (!doctor_id || !date) return res.status(400).json({ error: 'doctor_id و date مطلوبان' });

  const dr = (await pool.query('SELECT * FROM doctors WHERE id=$1', [doctor_id])).rows[0];
  if (!dr) return res.status(404).json({ error: 'الطبيب غير موجود' });

  const booked = await pool.query(
    `SELECT TO_CHAR(appointment_time,'HH24:MI') as t FROM appointments
     WHERE doctor_id=$1 AND appointment_date=$2 AND status!='cancelled'`,
    [doctor_id, date]
  );
  const bookedTimes = booked.rows.map(r => r.t);

  const slots = [];
  const [sh, sm] = dr.start_time.split(':').map(Number);
  const [eh, em] = dr.end_time.split(':').map(Number);
  let cur = sh * 60 + sm;
  const end = eh * 60 + em;

  while (cur < end) {
    const h = String(Math.floor(cur/60)).padStart(2,'0');
    const m = String(cur%60).padStart(2,'0');
    slots.push({ time: `${h}:${m}`, available: !bookedTimes.includes(`${h}:${m}`) });
    cur += dr.slot_duration || 30;
  }
  res.json(slots);
});

// ── Reports ───────────────────────────────────────────────
app.get('/api/reports/summary', auth(['admin','receptionist']), async (req, res) => {
  let { from, to } = req.query;
  if (!from || !to) {
    const d = new Date();
    from = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-01`;
    to   = d.toISOString().split('T')[0];
  }
  const [total, today, pending, completed, byDoctor, byService] = await Promise.all([
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date BETWEEN $1 AND $2`, [from, to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE appointment_date=CURRENT_DATE`),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='pending' AND appointment_date BETWEEN $1 AND $2`, [from, to]),
    pool.query(`SELECT COUNT(*) FROM appointments WHERE status='completed' AND appointment_date BETWEEN $1 AND $2`, [from, to]),
    pool.query(`SELECT d.name, COUNT(a.id) as count FROM appointments a LEFT JOIN doctors d ON a.doctor_id=d.id WHERE a.appointment_date BETWEEN $1 AND $2 GROUP BY d.name ORDER BY count DESC`, [from, to]),
    pool.query(`SELECT service, COUNT(*) as count FROM appointments WHERE appointment_date BETWEEN $1 AND $2 GROUP BY service ORDER BY count DESC LIMIT 8`, [from, to]),
  ]);
  res.json({
    total: +total.rows[0].count,
    today: +today.rows[0].count,
    pending: +pending.rows[0].count,
    completed: +completed.rows[0].count,
    byDoctor: byDoctor.rows,
    byService: byService.rows,
  });
});

// ── Notify (WhatsApp URL) ─────────────────────────────────
app.post('/api/appointments/:id/notify', auth(), async (req, res) => {
  const { action = 'confirmed' } = req.body;
  const appt = (await pool.query('SELECT * FROM appointments WHERE id=$1', [req.params.id])).rows[0];
  if (!appt) return res.status(404).json({ error: 'الموعد غير موجود' });
  const pt = (await pool.query('SELECT * FROM patients WHERE id=$1', [appt.patient_id])).rows[0];
  const dr = (await pool.query('SELECT name FROM doctors WHERE id=$1', [appt.doctor_id])).rows[0];

  const msgs = {
    confirmed: `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم تأكيد موعدك:\n\n📅 ${appt.appointment_date}\n⏰ ${String(appt.appointment_time).substring(0,5)}\n👨‍⚕️ ${dr?.name||'—'}\n🩺 ${appt.service}\n\n📍 بغداد - الحارثية - مقابل مول بغداد\n📞 07747881005`,
    reminder:   `🦷 *تذكير — رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nلديك موعد:\n📅 ${appt.appointment_date} - ⏰ ${String(appt.appointment_time).substring(0,5)}\n👨‍⚕️ ${dr?.name||'—'}\nنأمل حضورك في الوقت المحدد 🙏`,
    cancelled:  `🦷 *رواسي لطب الأسنان*\n\nعزيزي ${pt.name}،\nتم إلغاء موعدك.\nللحجز مجدداً: 07747881005`,
  };
  const msg = msgs[action] || msgs.confirmed;
  const waPhone = pt.phone.startsWith('0') ? '964' + pt.phone.slice(1) : pt.phone;
  const waUrl = `https://wa.me/${waPhone}?text=${encodeURIComponent(msg)}`;

  await pool.query(
    'INSERT INTO notifications_log (appointment_id, type, status, message) VALUES ($1,$2,$3,$4)',
    [appt.id, 'whatsapp', 'sent', msg]
  );
  res.json({ success: true, waUrl });
});

// ── Users ─────────────────────────────────────────────────
app.get('/api/users', auth(['admin']), async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,name,email,username,role,is_active,created_at FROM users ORDER BY created_at'
  );
  res.json(rows);
});

app.post('/api/users', auth(['admin']), async (req, res) => {
  const { name, email, password, role, doctor_id } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'الاسم وكلمة المرور مطلوبان' });
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    'INSERT INTO users (name,email,username,password,role,doctor_id) VALUES ($1,$2,$2,$3,$4,$5) RETURNING id,name,email,role',
    [name, email, hash, role||'receptionist', doctor_id||null]
  );
  res.json(rows[0]);
});

app.patch('/api/users/:id', auth(['admin']), async (req, res) => {
  const { is_active, role } = req.body;
  const { rows } = await pool.query(
    'UPDATE users SET is_active=COALESCE($1,is_active), role=COALESCE($2,role) WHERE id=$3 RETURNING id,name,email,role,is_active',
    [is_active ?? null, role||null, req.params.id]
  );
  res.json(rows[0]);
});

// ── Init & Start ──────────────────────────────────────────
initDB();

const PORT = process.env.PORT || 3001;
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => console.log(`🦷 Rawasi API on port ${PORT}`));
}

module.exports = app;
