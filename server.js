'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const cookieSession = require('cookie-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// ---------- Cấu hình (đổi bằng biến môi trường) ----------
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
const PUBLIC_DIR = path.join(__dirname, 'public');
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const MAX_PHOTOS_PER_USER = 30;
const MAX_PHOTOS_LISTED = 100;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- Khóa ký cookie ----------
function getSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const file = path.join(DATA_DIR, 'session-secret.txt');
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch {
    const secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(file, secret, { mode: 0o600 });
    return secret;
  }
}

// ---------- Cơ sở dữ liệu tệp JSON đơn giản ----------
const DB_FILE = path.join(DATA_DIR, 'db.json');
let db = { users: [], photos: [] };
if (fs.existsSync(DB_FILE)) {
  // Nếu tệp hỏng, để máy chủ báo lỗi thay vì âm thầm ghi đè mất dữ liệu.
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  db.users = db.users || [];
  db.photos = db.photos || [];
}
function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// ---------- Hàm tiện ích ----------
const clean = (value, max) =>
  String(value == null ? '' : value)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);

const isAdmin = (user) => !!user && ADMIN_USERNAME !== '' && user.username === ADMIN_USERNAME;
const publicUser = (user) => ({
  username: user.username,
  displayName: user.displayName,
  isAdmin: isAdmin(user),
});
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Nhận diện ảnh thật bằng chữ ký đầu tệp, không tin phần đuôi tên tệp.
function sniffImage(buf) {
  if (buf.length > 12 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return { ext: '.jpg' };
  }
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length > 12 && buf.subarray(0, 8).equals(png)) return { ext: '.png' };
  if (buf.length > 12 && buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') {
    return { ext: '.webp' };
  }
  return null;
}

const DUMMY_HASH = bcrypt.hashSync('mat-khau-gia-de-chong-do-thoi-gian', 10);

// ---------- Ứng dụng ----------
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ['https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        frameSrc: ['https://www.google.com', 'https://www.youtube.com'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json({ limit: '10kb' }));
app.use(
  cookieSession({
    name: 'bg_sess',
    keys: [getSessionSecret()],
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === '1', // đặt COOKIE_SECURE=1 khi chạy qua HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })
);

// Chặn yêu cầu ghi dữ liệu từ trang web khác (bổ sung cho SameSite).
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.get('origin');
  if (origin) {
    let ok = false;
    try {
      ok = new URL(origin).host === req.get('host');
    } catch {
      ok = false;
    }
    if (!ok) return res.status(403).json({ error: 'Yêu cầu không hợp lệ.' });
  }
  next();
});

app.use((req, res, next) => {
  const uid = req.session && req.session.uid;
  req.user = uid ? db.users.find((u) => u.id === uid) || null : null;
  next();
});

app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const requireAuth = (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Vui lòng đăng nhập để tiếp tục.' });
  next();
};

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Bạn thử quá nhiều lần. Vui lòng đợi ít phút rồi thử lại.' },
});
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Bạn tải ảnh quá nhiều trong một giờ. Vui lòng thử lại sau.' },
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 5, parts: 6 },
});
const receiveUpload = (req, res, next) => {
  upload.single('photo')(req, res, (err) => {
    if (!err) return next();
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Ảnh quá lớn, tối đa 5 MB.' });
    }
    return res.status(400).json({ error: 'Không đọc được tệp tải lên.' });
  });
};

// ---------- API tài khoản ----------
app.get('/api/me', (req, res) => {
  res.json({ user: req.user ? publicUser(req.user) : null });
});

app.post(
  '/api/register',
  authLimiter,
  wrap(async (req, res) => {
    const body = req.body || {};
    const username = String(body.username || '').trim().toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const displayName = clean(body.displayName, 40) || username;

    if (!/^[a-z0-9_.]{3,20}$/.test(username)) {
      return res.status(400).json({ error: 'Tên đăng nhập gồm 3–20 ký tự: chữ cái không dấu, số, dấu _ hoặc .' });
    }
    if (password.length < 8 || Buffer.byteLength(password) > 72) {
      return res.status(400).json({ error: 'Mật khẩu cần từ 8 ký tự và không quá 72 byte.' });
    }
    if (db.users.some((u) => u.username === username)) {
      return res.status(409).json({ error: 'Tên đăng nhập này đã có người dùng.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    if (db.users.some((u) => u.username === username)) {
      return res.status(409).json({ error: 'Tên đăng nhập này đã có người dùng.' });
    }
    const user = {
      id: crypto.randomUUID(),
      username,
      displayName,
      passwordHash,
      createdAt: new Date().toISOString(),
    };
    db.users.push(user);
    saveDb();

    req.session = { uid: user.id };
    res.status(201).json({ user: publicUser(user) });
  })
);

app.post(
  '/api/login',
  authLimiter,
  wrap(async (req, res) => {
    const body = req.body || {};
    const username = String(body.username || '').trim().toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const user = db.users.find((u) => u.username === username);
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) {
      return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu.' });
    }
    req.session = { uid: user.id };
    res.json({ user: publicUser(user) });
  })
);

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// ---------- API ảnh ----------
app.get('/api/photos', (req, res) => {
  const photos = db.photos
    .slice(-MAX_PHOTOS_LISTED)
    .reverse()
    .map((p) => ({
      id: p.id,
      url: '/uploads/' + p.file,
      caption: p.caption,
      author: p.authorName,
      createdAt: p.createdAt,
      canDelete: !!req.user && (req.user.id === p.userId || isAdmin(req.user)),
    }));
  res.json({ photos });
});

app.post(
  '/api/photos',
  requireAuth,
  uploadLimiter,
  receiveUpload,
  wrap(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'Hãy chọn một ảnh để tải lên.' });
    }
    const kind = sniffImage(req.file.buffer);
    if (!kind) {
      return res.status(400).json({ error: 'Chỉ chấp nhận ảnh JPG, PNG hoặc WebP hợp lệ.' });
    }
    const mine = db.photos.filter((p) => p.userId === req.user.id).length;
    if (mine >= MAX_PHOTOS_PER_USER && !isAdmin(req.user)) {
      return res.status(409).json({ error: `Mỗi tài khoản được đăng tối đa ${MAX_PHOTOS_PER_USER} ảnh. Hãy xóa bớt ảnh cũ.` });
    }

    const id = crypto.randomUUID();
    const file = id + kind.ext;
    await fs.promises.writeFile(path.join(UPLOAD_DIR, file), req.file.buffer, { flag: 'wx' });

    db.photos.push({
      id,
      file,
      caption: clean(req.body && req.body.caption, 140),
      userId: req.user.id,
      authorName: req.user.displayName,
      createdAt: new Date().toISOString(),
    });
    saveDb();
    res.status(201).json({ ok: true });
  })
);

app.delete(
  '/api/photos/:id',
  requireAuth,
  wrap(async (req, res) => {
    const index = db.photos.findIndex((p) => p.id === req.params.id);
    if (index < 0) return res.status(404).json({ error: 'Không tìm thấy ảnh.' });
    const photo = db.photos[index];
    if (photo.userId !== req.user.id && !isAdmin(req.user)) {
      return res.status(403).json({ error: 'Bạn không có quyền xóa ảnh này.' });
    }
    db.photos.splice(index, 1);
    saveDb();
    await fs.promises.unlink(path.join(UPLOAD_DIR, photo.file)).catch(() => {});
    res.json({ ok: true });
  })
);

app.use('/api', (req, res) => res.status(404).json({ error: 'Không tìm thấy.' }));

// ---------- Tệp tĩnh ----------
app.use(
  '/uploads',
  express.static(UPLOAD_DIR, { maxAge: '7d', immutable: true, index: false, dotfiles: 'deny' })
);
app.use(express.static(PUBLIC_DIR));

// ---------- Xử lý lỗi ----------
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Dữ liệu gửi lên không hợp lệ.' });
  }
  console.error(err);
  res.status(500).json({ error: 'Máy chủ gặp lỗi, vui lòng thử lại sau.' });
});

app.listen(PORT, () => {
  console.log(`Trang THPT Bình Gia đang chạy tại http://localhost:${PORT}`);
  if (!ADMIN_USERNAME) {
    console.log('Gợi ý: đặt ADMIN_USERNAME=<tên tài khoản> để cho một tài khoản quyền xóa mọi ảnh.');
  }
});
