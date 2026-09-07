import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import Stripe from 'stripe';
import nodemailer from 'nodemailer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 3000);
const appOrigin = process.env.APP_ORIGIN || `http://localhost:${port}`;
const jwtSecret = process.env.JWT_SECRET || 'development-only-change-this-secret';
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
const db = new Database(path.join(__dirname, 'data', 'fmodas.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', phone TEXT, address TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, gender TEXT NOT NULL DEFAULT 'Unissex', cost_price INTEGER NOT NULL, sale_price INTEGER NOT NULL, stock INTEGER NOT NULL DEFAULT 0, photos_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', subtotal INTEGER NOT NULL, shipping INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL, stripe_session_id TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id));
  CREATE TABLE IF NOT EXISTS order_items (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL, product_id INTEGER NOT NULL, quantity INTEGER NOT NULL, unit_price INTEGER NOT NULL, FOREIGN KEY(order_id) REFERENCES orders(id), FOREIGN KEY(product_id) REFERENCES products(id));
  CREATE TABLE IF NOT EXISTS password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT UNIQUE NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id));
`);
const uploadsDir = path.join(__dirname, 'uploads');
const upload = multer({ dest: uploadsDir, limits: { fileSize: 5 * 1024 * 1024, files: 8 }, fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) });
const stripe = process.env.STRIPE_SECRET_KEY?.startsWith('sk_') ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: Number(process.env.SMTP_PORT) === 465, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } }) : null;
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const hashPassword = password => bcrypt.hash(password, 12);
const cents = value => { const normalized = String(value ?? '0').replace(/[^0-9,.-]/g, '').replace('.', '').replace(',', '.'); return Math.round(Number(normalized || 0) * 100); };
const signUser = user => jwt.sign({ id: user.id, role: user.role, email: user.email }, jwtSecret, { expiresIn: '8h' });
function setSession(res, user) { res.cookie('fmodas_session', signUser(user), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }); }
function requireAuth(req, res, next) { try { const token = req.cookies.fmodas_session; if (!token) return res.status(401).json({ error: 'Autenticação necessária.' }); req.user = jwt.verify(token, jwtSecret); next(); } catch { res.status(401).json({ error: 'Sessão inválida ou expirada.' }); } }
function requireAdmin(req, res, next) { if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Acesso administrativo necessário.' }); next(); }
function publicProduct(row) { return { ...row, cost_price: row.cost_price / 100, sale_price: row.sale_price / 100, photos: JSON.parse(row.photos_json || '[]') }; }

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: (origin, callback) => callback(null, !origin || origin === appOrigin), credentials: true }));
app.use(cookieParser());
app.use('/api/webhooks/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(uploadsDir));
app.use(express.static(__dirname));

app.post('/api/auth/register', authLimiter, async (req, res) => { const { name, email, password } = req.body; if (!name || !email || !password || password.length < 8) return res.status(400).json({ error: 'Nome, e-mail e senha com 8 caracteres são obrigatórios.' }); try { const hash = await hashPassword(password); const result = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)').run(name.trim(), email.toLowerCase().trim(), hash); const user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(result.lastInsertRowid); setSession(res, user); res.status(201).json({ user }); } catch (error) { res.status(error.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ error: 'Não foi possível criar a conta.' }); } });
app.post('/api/auth/login', authLimiter, async (req, res) => { const { email, password } = req.body; const normalized = String(email || '').toLowerCase().trim(); let user = db.prepare('SELECT * FROM users WHERE email=?').get(normalized); if (!user && normalized === String(process.env.ADMIN_EMAIL || 'admin@fmodas.com').toLowerCase()) { const adminPassword = process.env.ADMIN_PASSWORD; if (adminPassword && await bcrypt.compare(password || '', await hashPassword(adminPassword))) { const hash = await hashPassword(adminPassword); const result = db.prepare('INSERT OR IGNORE INTO users (name,email,password_hash,role) VALUES (?,?,?,?)').run('Administrador', normalized, hash, 'admin'); user = db.prepare('SELECT * FROM users WHERE id=? OR email=?').get(result.lastInsertRowid, normalized); } } if (!user || !(await bcrypt.compare(password || '', user.password_hash))) return res.status(401).json({ error: 'E-mail ou senha inválidos.' }); setSession(res, user); res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } }); });
app.post('/api/auth/logout', (_req, res) => res.clearCookie('fmodas_session').json({ ok: true }));
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: db.prepare('SELECT id,name,email,role,phone,address FROM users WHERE id=?').get(req.user.id) }));
app.post('/api/auth/forgot-password', authLimiter, async (req, res) => { const user = db.prepare('SELECT id,email FROM users WHERE email=?').get(String(req.body.email || '').toLowerCase().trim()); if (user && mailer) { const rawToken = crypto.randomBytes(32).toString('hex'); const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex'); db.prepare('INSERT INTO password_resets (user_id,token_hash,expires_at) VALUES (?,?,?)').run(user.id, tokenHash, Date.now() + 30 * 60 * 1000); await mailer.sendMail({ from: process.env.MAIL_FROM, to: user.email, subject: 'Recuperação de senha FMODAS', text: `Acesse ${appOrigin}/cliente.html#reset-${rawToken} para criar uma nova senha.` }); } res.json({ message: 'Se o e-mail existir, enviaremos as instruções de recuperação.' }); });
app.get('/api/products', (req, res) => { const rows = db.prepare('SELECT * FROM products WHERE stock > 0 ORDER BY created_at DESC').all(); res.json({ products: rows.map(publicProduct) }); });
app.post('/api/products', requireAuth, requireAdmin, upload.array('photos', 8), (req, res) => { const { name, description = '', category, gender = 'Unissex', costPrice, salePrice, stock = 0 } = req.body; if (!name || !category || !salePrice) return res.status(400).json({ error: 'Nome, categoria e preço de venda são obrigatórios.' }); const uploadedPhotos = (req.files || []).map(file => `/uploads/${file.filename}`); const linkedPhotos = req.body.photoUrls ? JSON.parse(req.body.photoUrls) : []; const photos = [...uploadedPhotos, ...linkedPhotos].slice(0, 8); const result = db.prepare('INSERT INTO products (name,description,category,gender,cost_price,sale_price,stock,photos_json) VALUES (?,?,?,?,?,?,?,?)').run(name, description, category, gender, cents(costPrice || 0), cents(salePrice), Number(stock), JSON.stringify(photos)); res.status(201).json({ product: publicProduct(db.prepare('SELECT * FROM products WHERE id=?').get(result.lastInsertRowid)) }); });
app.patch('/api/products/:id', requireAuth, requireAdmin, upload.array('photos', 8), (req, res) => { const product = db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id); if (!product) return res.status(404).json({ error: 'Produto não encontrado.' }); const photos = req.files?.length ? req.files.map(file => `/uploads/${file.filename}`) : JSON.parse(product.photos_json || '[]'); db.prepare('UPDATE products SET name=?,description=?,category=?,gender=?,cost_price=?,sale_price=?,stock=?,photos_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.body.name ?? product.name, req.body.description ?? product.description, req.body.category ?? product.category, req.body.gender ?? product.gender, req.body.costPrice ? cents(req.body.costPrice) : product.cost_price, req.body.salePrice ? cents(req.body.salePrice) : product.sale_price, req.body.stock ?? product.stock, JSON.stringify(photos), req.params.id); res.json({ product: publicProduct(db.prepare('SELECT * FROM products WHERE id=?').get(req.params.id)) }); });
app.delete('/api/products/:id', requireAuth, requireAdmin, (req, res) => { db.prepare('DELETE FROM products WHERE id=?').run(req.params.id); res.status(204).end(); });
app.get('/api/orders', requireAuth, (req, res) => { const orders = req.user.role === 'admin' ? db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all() : db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC').all(req.user.id); res.json({ orders }); });
app.post('/api/checkout', requireAuth, async (req, res) => { const items = Array.isArray(req.body.items) ? req.body.items : []; if (!items.length) return res.status(400).json({ error: 'Carrinho vazio.' }); const products = items.map(item => ({ item, product: db.prepare('SELECT * FROM products WHERE id=?').get(item.productId) })); if (products.some(({ product, item }) => !product || product.stock < Number(item.quantity))) return res.status(409).json({ error: 'Produto sem estoque suficiente.' }); const subtotal = products.reduce((sum, { product, item }) => sum + product.sale_price * Number(item.quantity), 0); const shipping = subtotal >= 25000 ? 0 : 1990; const total = subtotal + shipping; const createOrder = db.transaction(() => { const order = db.prepare('INSERT INTO orders (user_id,subtotal,shipping,total) VALUES (?,?,?,?)').run(req.user.id, subtotal, shipping, total); const insertItem = db.prepare('INSERT INTO order_items (order_id,product_id,quantity,unit_price) VALUES (?,?,?,?)'); const updateStock = db.prepare('UPDATE products SET stock=stock-? WHERE id=?'); products.forEach(({ product, item }) => { insertItem.run(order.lastInsertRowid, product.id, item.quantity, product.sale_price); updateStock.run(item.quantity, product.id); }); return order.lastInsertRowid; }); const orderId = createOrder(); if (!stripe) return res.status(201).json({ orderId, paymentRequired: true, message: 'Pedido criado. Configure Stripe para gerar o pagamento.' }); const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: products.map(({ product, item }) => ({ price_data: { currency: 'brl', product_data: { name: product.name }, unit_amount: product.sale_price }, quantity: Number(item.quantity) })), success_url: `${appOrigin}/cliente.html#pedido-sucesso`, cancel_url: `${appOrigin}/cliente.html#cart`, metadata: { orderId: String(orderId) } }); db.prepare('UPDATE orders SET stripe_session_id=? WHERE id=?').run(session.id, orderId); res.status(201).json({ orderId, checkoutUrl: session.url }); });
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => { if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.status(503).end(); try { const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET); if (event.type === 'checkout.session.completed') db.prepare("UPDATE orders SET status='paid' WHERE stripe_session_id=?").run(event.data.object.id); res.json({ received: true }); } catch { res.status(400).send('Webhook inválido'); } });
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.listen(port, () => console.log(`FMODAS API: ${appOrigin}`));
