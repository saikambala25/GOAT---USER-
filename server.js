'use strict';

const express      = require('express');
const mongoose     = require('mongoose');
const cors         = require('cors');
const path         = require('path');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const multer       = require('multer');
const crypto       = require('crypto');
require('dotenv').config();

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────
const PORT         = process.env.PORT        || 3000;
const JWT_SECRET   = process.env.JWT_SECRET  || 'change-this-secret-key-123';
const MONGODB_URI  = process.env.MONGODB_URI || 'mongodb://localhost:27017/livestockmart';
const UPI_ID       = process.env.UPI_ID      || 'sai.kambala@ybl';
const IS_PROD      = process.env.NODE_ENV === 'production';

// Session is 5 hours to match the frontend inactivity timeout
const SESSION_HOURS = 5;
const SESSION_MS    = SESSION_HOURS * 60 * 60 * 1000;

// ─────────────────────────────────────────────
//  MONGODB — serverless-safe connection cache
// ─────────────────────────────────────────────
let _db = global.__mongoConn || null;

async function connectDB() {
    if (_db && mongoose.connection.readyState === 1) return _db;
    if (!_db) {
        _db = global.__mongoConn = mongoose.connect(MONGODB_URI, {
            bufferCommands:            false,
            serverSelectionTimeoutMS:  8000,
            socketTimeoutMS:           45000,
            maxPoolSize:               10,
        }).then(m => {
            console.log('✅ MongoDB connected');
            return m;
        }).catch(e => {
            _db = global.__mongoConn = null;
            throw e;
        });
    }
    await _db;
    return mongoose.connection;
}

// ─────────────────────────────────────────────
//  MODELS
// ─────────────────────────────────────────────

// --- User ---
const addressSchema = new mongoose.Schema({
    label:   { type: String, default: '' },
    name:    String,
    line1:   String,
    line2:   { type: String, default: '' },
    city:    String,
    state:   String,
    pincode: String,
    phone:   String,
}, { _id: false });

const cartItemSchema = new mongoose.Schema({
    _id:      { type: String },
    name:     String,
    price:    Number,
    breed:    String,
    type:     String,
    weight:   String,
    selected: { type: Boolean, default: true },
}, { _id: false });

const notificationSchema = new mongoose.Schema({
    id:        String,
    title:     String,
    message:   String,
    icon:      { type: String, default: 'bell' },
    color:     { type: String, default: 'blue' },
    timestamp: { type: Number, default: Date.now },
    seen:      { type: Boolean, default: false },
}, { _id: false });

const userSchema = new mongoose.Schema({
    name:          { type: String, required: true, trim: true },
    email:         { type: String, required: true, unique: true, lowercase: true, trim: true },
    password:      { type: String, required: true },
    cart:          [cartItemSchema],
    wishlist:      [{ type: String }],
    addresses:     [addressSchema],
    notifications: [notificationSchema],
    createdAt:     { type: Date, default: Date.now },
});

const bcrypt = require('bcryptjs');
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (e) { next(e); }
});
userSchema.methods.comparePassword = function (pwd) {
    return bcrypt.compare(pwd, this.password);
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

// --- Livestock ---
const livestockSchema = new mongoose.Schema({
    name:   { type: String, required: true },
    type:   { type: String, required: true },   // Goat | Sheep
    breed:  { type: String, required: true },
    age:    { type: String, default: 'N/A' },
    weight: { type: String, default: 'N/A' },
    price:  { type: Number, required: true },
    tags:   [String],
    status: { type: String, default: 'Available' },
    image:  { data: Buffer, contentType: String },
    images: [{ data: Buffer, contentType: String }],
    createdAt: { type: Date, default: Date.now },
});
const Livestock = mongoose.models.Livestock || mongoose.model('Livestock', livestockSchema);

// --- Order ---
const orderSchema = new mongoose.Schema({
    customer:  { type: String, required: true },
    userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    date:      { type: String, required: true },
    items: [{
        _id:    String,
        name:   String,
        price:  Number,
        breed:  String,
        type:   String,   // ← FIXED: was missing
        weight: String,
    }],
    total:           { type: Number, required: true },
    status:          { type: String, default: 'Processing' },
    rejectionReason: { type: String, default: '' },
    address: {
        name: String, phone: String,
        line1: String, line2: String,
        city: String, state: String, pincode: String,
    },
    paymentProof: { data: Buffer, contentType: String },
    createdAt:    { type: Date, default: Date.now },
});
const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);

// --- ProofHash (prevent duplicate payment screenshots) ---
const proofHashSchema = new mongoose.Schema({
    hash:      { type: String, required: true, unique: true },
    orderId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Order', required: true },
    createdAt: { type: Date, default: Date.now },
});
const ProofHash = mongoose.models.ProofHash || mongoose.model('ProofHash', proofHashSchema);

// --- AdminNotification ---
const adminNotifSchema = new mongoose.Schema({
    message:   String,
    type:      { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
    orderId:   mongoose.Schema.Types.ObjectId,
    read:      { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
});
const AdminNotification = mongoose.models.AdminNotification || mongoose.model('AdminNotification', adminNotifSchema);

// --- SystemNotification (broadcast to all users) ---
const sysNotifSchema = new mongoose.Schema({
    id:        { type: String, required: true, unique: true },
    title:     String,
    message:   String,
    icon:      { type: String, default: 'bell' },
    color:     { type: String, default: 'blue' },
    createdAt: { type: Date, default: Date.now },
});
const SystemNotification = mongoose.models.SystemNotification || mongoose.model('SystemNotification', sysNotifSchema);

// ─────────────────────────────────────────────
//  EXPRESS SETUP
// ─────────────────────────────────────────────
const app = express();

// Connect DB before every request
app.use(async (req, res, next) => {
    try   { await connectDB(); next(); }
    catch (e) {
        console.error('❌ DB Error:', e.message);
        res.status(500).json({ error: 'Database connection failed. Please try again.' });
    }
});

const upload = multer({
    storage: multer.memoryStorage(),
    limits:  { fileSize: 10 * 1024 * 1024 },   // 10 MB
    fileFilter(req, file, cb) {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only image files allowed'));
    },
});

// CORS — allow the deployed frontend origin plus localhost dev
const allowedOrigins = [
    'https://goat-user-latest.vercel.app',
    'http://localhost:3000',
    'http://localhost:5000',
];
app.use(cors({
    origin(origin, cb) {
        if (!origin || allowedOrigins.some(o => origin.startsWith(o))) return cb(null, true);
        cb(null, true);  // Accept all for now (tighten in production if needed)
    },
    credentials:          true,
    methods:              ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders:       ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200,
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());

// Serve static files with aggressive caching for images/JS/CSS
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag:   true,
    setHeaders(res, filePath) {
        if (/\.(jpg|jpeg|png|gif|webp|svg|ico)$/i.test(filePath)) {
            res.setHeader('Cache-Control', 'public, max-age=86400, stale-while-revalidate=3600');
        }
    },
}));

// ─────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────
function createToken(user) {
    return jwt.sign(
        { id: user._id.toString(), email: user.email, name: user.name },
        JWT_SECRET,
        { expiresIn: `${SESSION_HOURS}h` }   // 5 hours — matches frontend
    );
}

function setAuthCookie(res, token) {
    res.cookie('token', token, {
        httpOnly: true,
        sameSite: IS_PROD ? 'none' : 'lax',
        secure:   IS_PROD,
        maxAge:   SESSION_MS,
        path:     '/',
    });
}

function clearAuthCookie(res) {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: IS_PROD ? 'none' : 'lax',
        secure:   IS_PROD,
        path:     '/',
    });
}

function authMiddleware(req, res, next) {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = { id: decoded.id, email: decoded.email, name: decoded.name };

        // Auto-refresh: if token expires within 1 hour, issue a new one
        const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);
        if (expiresIn < 3600) {
            setAuthCookie(res, createToken({ _id: decoded.id, email: decoded.email, name: decoded.name }));
        }
        next();
    } catch (err) {
        clearAuthCookie(res);
        return res.status(401).json({ message: 'Session expired. Please login again.' });
    }
}

function getFileHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

function sendImageResponse(res, imageObj, maxAgeSeconds = 86400) {
    if (!imageObj?.data) return res.status(404).send('Image not found');
    res.set({
        'Content-Type':  imageObj.contentType || 'image/jpeg',
        'Cache-Control': `public, max-age=${maxAgeSeconds}, stale-while-revalidate=3600`,
        'ETag':          getFileHash(imageObj.data).slice(0, 16),
    });
    // Conditional GET support
    const etag = res.getHeader('ETag');
    if (req => req.headers['if-none-match'] === etag) return res.status(304).end();
    res.send(imageObj.data);
}

// ─────────────────────────────────────────────
//  AUTO-EXPIRE UNPAID ORDERS (lazy — runs on
//  admin fetch and order creation)
// ─────────────────────────────────────────────
async function expireUnpaidOrders() {
    try {
        const cutoff = new Date(Date.now() - 30 * 60 * 1000);
        const expired = await Order.find({ status: 'Pending', createdAt: { $lt: cutoff } });
        for (const order of expired) {
            order.status = 'Cancelled';
            await order.save();
            const ids = order.items.map(i => i._id);
            if (ids.length) await Livestock.updateMany({ _id: { $in: ids } }, { $set: { status: 'Available' } });
            await AdminNotification.create({
                message: `System: Order #${order._id.toString().slice(-6)} auto-expired (unpaid > 30 min).`,
                type: 'warning', orderId: order._id,
            });
        }
    } catch (e) { console.error('Auto-expire error:', e.message); }
}

// Keep alive on long-running servers; no-op on serverless
if (!IS_PROD) setInterval(expireUnpaidOrders, 60_000);

// ─────────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
    status:   'UP',
    uptime:   Math.round(process.uptime()),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    time:     new Date().toISOString(),
}));

// ─────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name?.trim() || !email?.trim() || !password) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters.' });
        }
        const existing = await User.findOne({ email: email.toLowerCase().trim() });
        if (existing) return res.status(409).json({ message: 'An account with this email already exists.' });

        const user = new User({ name: name.trim(), email: email.toLowerCase().trim(), password });
        await user.save();

        setAuthCookie(res, createToken(user));
        res.status(201).json({ user: { id: user._id, name: user.name, email: user.email } });
    } catch (e) {
        console.error('Register error:', e.message);
        res.status(500).json({ message: 'Registration failed. Please try again.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });

        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        setAuthCookie(res, createToken(user));
        res.json({ user: { id: user._id, name: user.name, email: user.email } });
    } catch (e) {
        console.error('Login error:', e.message);
        res.status(500).json({ message: 'Login failed. Please try again.' });
    }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ user: req.user });
});

app.post('/api/auth/logout', (req, res) => {
    clearAuthCookie(res);
    res.json({ message: 'Logged out successfully.' });
});

// ─────────────────────────────────────────────
//  USER STATE  (cart + wishlist + addresses + notifications)
// ─────────────────────────────────────────────
app.get('/api/user/state', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id, 'cart wishlist addresses notifications');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.json({
            cart:          user.cart          || [],
            wishlist:      user.wishlist      || [],
            addresses:     user.addresses     || [],
            notifications: user.notifications || [],
        });
    } catch (e) {
        console.error('loadState error:', e.message);
        res.status(500).json({ error: 'Could not load user data.' });
    }
});

app.put('/api/user/state', authMiddleware, async (req, res) => {
    try {
        const { cart, wishlist, addresses, notifications } = req.body;
        await User.findByIdAndUpdate(req.user.id, {
            $set: {
                ...(Array.isArray(cart)          && { cart }),
                ...(Array.isArray(wishlist)       && { wishlist }),
                ...(Array.isArray(addresses)      && { addresses }),
                ...(Array.isArray(notifications)  && { notifications }),
            },
        }, { new: true, runValidators: false });
        res.json({ success: true, message: 'State saved.' });
    } catch (e) {
        console.error('saveState error:', e.message);
        res.status(500).json({ error: 'Could not save user data.' });
    }
});

// ─────────────────────────────────────────────
//  DEDICATED ADDRESS ROUTES
// ─────────────────────────────────────────────
app.get('/api/user/addresses', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id, 'addresses');
        if (!user) return res.status(404).json({ message: 'User not found.' });
        res.json({ addresses: user.addresses || [] });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/user/address', authMiddleware, async (req, res) => {
    try {
        const { label, name, line1, line2 = '', city, state, pincode, phone } = req.body;
        if (!name || !line1 || !city || !state || !pincode || !phone) {
            return res.status(400).json({ message: 'All address fields are required.' });
        }
        const user = await User.findById(req.user.id, 'addresses');
        if (!user) return res.status(404).json({ message: 'User not found.' });

        const exists = user.addresses.some(a =>
            a.name === name && a.phone === phone && a.line1 === line1 && a.pincode === pincode
        );
        if (exists) return res.json({ success: true, saved: false, message: 'Address already saved.' });

        const addressLabel = label || (user.addresses.length === 0 ? 'Default' : `Address ${user.addresses.length + 1}`);
        await User.findByIdAndUpdate(req.user.id, {
            $push: { addresses: { label: addressLabel, name, line1, line2, city, state, pincode, phone } },
        });
        res.json({ success: true, saved: true, message: 'Address saved permanently.' });
    } catch (e) {
        console.error('saveAddress error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/user/address/:index', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });
        const idx = parseInt(req.params.index, 10);
        if (isNaN(idx) || idx < 0 || idx >= user.addresses.length) {
            return res.status(400).json({ message: 'Invalid address index.' });
        }
        Object.assign(user.addresses[idx], req.body);
        await user.save();
        res.json({ success: true, addresses: user.addresses });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/user/address/:index', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found.' });
        const idx = parseInt(req.params.index, 10);
        if (isNaN(idx) || idx < 0 || idx >= user.addresses.length) {
            return res.status(400).json({ message: 'Invalid address index.' });
        }
        user.addresses.splice(idx, 1);
        await user.save();
        res.json({ success: true, addresses: user.addresses });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  SYSTEM NOTIFICATIONS  (broadcast to all users)
// ─────────────────────────────────────────────
app.get('/api/notifications', async (req, res) => {
    try {
        // Return last 20 system-wide notifications (newest first)
        const notifs = await SystemNotification.find()
            .sort({ createdAt: -1 })
            .limit(20)
            .lean();
        res.json(notifs);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Admin: create a broadcast notification
app.post('/api/admin/notifications/broadcast', async (req, res) => {
    try {
        const { title, message, icon = 'bell', color = 'blue' } = req.body;
        if (!message) return res.status(400).json({ message: 'Message required.' });
        await SystemNotification.create({
            id: 'sys_' + Date.now(),
            title: title || 'Notice',
            message, icon, color,
        });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  LIVESTOCK  (public read, admin write)
// ─────────────────────────────────────────────
app.get('/api/livestock', async (req, res) => {
    try {
        // Exclude binary image blobs — send metadata only
        const items = await Livestock.find({}, '-image -images').sort({ createdAt: -1 }).lean();
        // Attach imageCount so frontend knows how many images exist
        const withCount = await Promise.all(items.map(async item => {
            const full = await Livestock.findById(item._id, 'images image').lean();
            const imageCount = full?.images?.length || (full?.image?.data ? 1 : 0);
            return { ...item, imageCount };
        }));
        res.json(withCount);
    } catch (e) {
        console.error('livestock fetch error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// Single image (backwards compat)
app.get('/api/livestock/image/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        const item = await Livestock.findById(req.params.id, 'image images').lean();
        if (!item) return res.status(404).send('Not found');
        // Prefer images[0] if available, fallback to legacy image
        const img = item.images?.[0] || item.image;
        if (!img?.data) return res.status(404).send('No image');

        res.set({
            'Content-Type':  img.contentType || 'image/jpeg',
            'Cache-Control': 'public, max-age=86400',
            'ETag':          `"${req.params.id}-0"`,
        });
        if (req.headers['if-none-match'] === `"${req.params.id}-0"`) return res.status(304).end();
        res.send(img.data);
    } catch (e) { res.status(500).send('Server error'); }
});

// Image by index
app.get('/api/livestock/image/:id/:index', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        const idx  = parseInt(req.params.index, 10);
        const item = await Livestock.findById(req.params.id, 'images image').lean();
        if (!item) return res.status(404).send('Not found');

        const img = item.images?.[idx] || (idx === 0 ? item.image : null);
        if (!img?.data) return res.status(404).send('No image at index');

        const etag = `"${req.params.id}-${idx}"`;
        res.set({
            'Content-Type':  img.contentType || 'image/jpeg',
            'Cache-Control': 'public, max-age=86400',
            'ETag':          etag,
        });
        if (req.headers['if-none-match'] === etag) return res.status(304).end();
        res.send(img.data);
    } catch (e) { res.status(500).send('Server error'); }
});

// ─────────────────────────────────────────────
//  ADMIN — LIVESTOCK CRUD
// ─────────────────────────────────────────────
app.get('/api/admin/livestock', async (req, res) => {
    try {
        const items = await Livestock.find({}, '-image -images').sort({ createdAt: -1 });
        res.json({ livestock: items });
    } catch (e) { res.status(500).json({ message: 'Failed', error: e.message }); }
});

app.post('/api/admin/livestock', upload.array('images', 10), async (req, res) => {
    try {
        const { name, type, breed, price, tags, status, weight, age } = req.body;
        if (!name || !type || !breed || !price) {
            return res.status(400).json({ message: 'name, type, breed, price are required.' });
        }
        const images = (req.files || []).map(f => ({ data: f.buffer, contentType: f.mimetype }));
        const image  = images[0];
        const item   = new Livestock({
            name: name.trim(), type, breed,
            age:    age    || (weight ? `${weight} kg` : 'N/A'),
            weight: weight || 'N/A',
            price:  parseFloat(price) || 0,
            tags:   typeof tags === 'string' ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
            status: status || 'Available',
            image, images,
        });
        await item.save();
        res.status(201).json({ ...item.toObject(), image: undefined, images: undefined });
    } catch (e) {
        console.error('Create livestock error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/admin/livestock/:id', upload.array('images', 10), async (req, res) => {
    try {
        const updates = { ...req.body };
        if (updates.price) updates.price = parseFloat(updates.price);
        if (req.files?.length) {
            updates.images = req.files.map(f => ({ data: f.buffer, contentType: f.mimetype }));
            updates.image  = updates.images[0];
        }
        const item = await Livestock.findByIdAndUpdate(req.params.id, updates, { new: true });
        if (!item) return res.status(404).json({ message: 'Livestock not found.' });
        res.json({ ...item.toObject(), image: undefined, images: undefined });
    } catch (e) { res.status(500).json({ message: 'Update failed', error: e.message }); }
});

app.delete('/api/admin/livestock/:id', async (req, res) => {
    try {
        await Livestock.findByIdAndDelete(req.params.id);
        res.status(204).send();
    } catch (e) { res.status(500).json({ message: 'Delete failed', error: e.message }); }
});

// ─────────────────────────────────────────────
//  ADMIN — ORDERS
// ─────────────────────────────────────────────
app.get('/api/admin/orders', async (req, res) => {
    try {
        await expireUnpaidOrders();
        const orders = await Order.find({}, '-paymentProof.data').sort({ createdAt: -1 });
        res.json({ orders });
    } catch (e) { res.status(500).json({ message: 'Failed to load orders', error: e.message }); }
});

app.get('/api/admin/orders/proof/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id, 'paymentProof');
        if (!order?.paymentProof?.data) return res.status(404).send('No proof found');
        res.set('Content-Type', order.paymentProof.contentType);
        res.send(order.paymentProof.data);
    } catch (e) { res.status(500).send('Server error'); }
});

app.put('/api/admin/orders/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            { new: true }
        );
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        // Notify the user of status change
        await User.findByIdAndUpdate(order.userId, {
            $push: {
                notifications: {
                    id:        'status_' + Date.now(),
                    title:     'Order Update',
                    message:   `Your Order #${order._id.toString().slice(-6)} is now: ${req.body.status}`,
                    icon:      'package',
                    color:     req.body.status === 'Delivered' ? 'green' : 'blue',
                    timestamp: Date.now(),
                    seen:      false,
                },
            },
        });
        res.json(order);
    } catch (e) { res.status(500).json({ message: 'Update failed', error: e.message }); }
});

app.put('/api/admin/orders/:id/reject', async (req, res) => {
    try {
        const { reason = 'Invalid payment proof.' } = req.body;
        const order = await Order.findByIdAndUpdate(
            req.params.id,
            { status: 'Payment Rejected', rejectionReason: reason },
            { new: true }
        );
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        // Restock
        const ids = order.items.map(i => i._id);
        if (ids.length) await Livestock.updateMany({ _id: { $in: ids } }, { $set: { status: 'Available' } });

        // Notify user
        await User.findByIdAndUpdate(order.userId, {
            $push: {
                notifications: {
                    id:        'rej_' + Date.now(),
                    title:     'Payment Rejected',
                    message:   `Order #${order._id.toString().slice(-6)} was rejected: ${reason}. Items have been restocked.`,
                    icon:      'x-circle',
                    color:     'red',
                    timestamp: Date.now(),
                    seen:      false,
                },
            },
        });
        res.json({ success: true, message: 'Order rejected and items restocked.' });
    } catch (e) {
        console.error('Reject error:', e.message);
        res.status(500).json({ error: e.message });
    }
});

// ─────────────────────────────────────────────
//  ADMIN — USERS & NOTIFICATIONS
// ─────────────────────────────────────────────
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find({}, 'name email createdAt').sort({ createdAt: -1 });
        res.json({ users });
    } catch (e) { res.status(500).json({ message: 'Failed', error: e.message }); }
});

app.get('/api/admin/notifications', async (req, res) => {
    try {
        const notifs = await AdminNotification.find().sort({ createdAt: -1 }).limit(50);
        res.json({ notifications: notifs });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/notifications/clear', async (req, res) => {
    try {
        await AdminNotification.deleteMany({});
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
//  USER ORDERS
// ─────────────────────────────────────────────
app.get('/api/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user.id }, '-paymentProof.data').sort({ createdAt: -1 });
        res.json(orders);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/orders', authMiddleware, upload.single('paymentProof'), async (req, res) => {
    try {
        await expireUnpaidOrders();

        const items   = JSON.parse(req.body.items   || '[]');
        const address = JSON.parse(req.body.address || '{}');
        const total   = parseFloat(req.body.total)  || 0;
        const date    = req.body.date               || new Date().toLocaleString('en-IN');

        if (!items.length)  return res.status(400).json({ message: 'No items in order.' });
        if (!address.name)  return res.status(400).json({ message: 'Delivery address is required.' });
        if (!req.file)      return res.status(400).json({ message: 'Payment proof (screenshot) is required.' });

        // Duplicate proof check
        const fileHash    = getFileHash(req.file.buffer);
        const existingProof = await ProofHash.findOne({ hash: fileHash });
        if (existingProof) {
            return res.status(400).json({ message: 'This payment screenshot has already been used. Please upload a new one.' });
        }

        const order = new Order({
            customer:     req.user.name,
            userId:       req.user.id,
            date, items, address, total,
            paymentProof: { data: req.file.buffer, contentType: req.file.mimetype },
        });
        await order.save();

        // Store proof hash to prevent reuse
        await ProofHash.create({ hash: fileHash, orderId: order._id });

        // Mark livestock as sold
        const itemIds = items.map(i => i._id).filter(Boolean);
        if (itemIds.length) await Livestock.updateMany({ _id: { $in: itemIds } }, { $set: { status: 'Sold' } });

        // Auto-save delivery address permanently
        const userDoc = await User.findById(req.user.id, 'addresses cart');
        const addrExists = userDoc?.addresses.some(a =>
            a.name === address.name && a.phone === address.phone &&
            a.line1 === address.line1 && a.pincode === address.pincode
        );
        const addrLabel = !userDoc?.addresses?.length ? 'Default' : `Address ${(userDoc?.addresses?.length || 0) + 1}`;

        await User.findByIdAndUpdate(req.user.id, {
            $set:  { cart: [] },
            ...(!addrExists && { $push: { addresses: { ...address, label: address.label || addrLabel } } }),
        });

        // Notify admin
        await AdminNotification.create({
            message: `New order #${order._id.toString().slice(-6)} by ${req.user.name} — ₹${total.toLocaleString('en-IN')}`,
            type: 'success', orderId: order._id,
        });

        res.status(201).json({ success: true, order: { ...order.toObject(), paymentProof: undefined } });
    } catch (e) {
        console.error('Create order error:', e.message);
        res.status(500).json({ error: 'Order creation failed. Please try again.' });
    }
});

app.put('/api/orders/:id/cancel', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
        if (!order) return res.status(404).json({ message: 'Order not found.' });
        if (!['Processing', 'Pending'].includes(order.status)) {
            return res.status(400).json({ message: `Cannot cancel an order with status "${order.status}".` });
        }
        order.status = 'Cancelled';
        await order.save();

        const ids = order.items.map(i => i._id).filter(Boolean);
        if (ids.length) await Livestock.updateMany({ _id: { $in: ids } }, { $set: { status: 'Available' } });

        // Allow proof reuse after cancellation
        await ProofHash.findOneAndDelete({ orderId: order._id });

        res.json({ success: true, message: 'Order cancelled. Items have been restocked.' });
    } catch (e) {
        console.error('Cancel error:', e.message);
        res.status(500).json({ message: 'Cancellation failed.' });
    }
});

app.put('/api/orders/:id/reupload', authMiddleware, upload.single('paymentProof'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });

        const fileHash = getFileHash(req.file.buffer);
        const dup = await ProofHash.findOne({ hash: fileHash });
        if (dup && dup.orderId.toString() !== req.params.id) {
            return res.status(400).json({ message: 'This screenshot has already been used for another order.' });
        }

        const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        await Order.findByIdAndUpdate(req.params.id, {
            status:           'Processing',
            rejectionReason:  '',
            paymentProof:     { data: req.file.buffer, contentType: req.file.mimetype },
        });
        await ProofHash.findOneAndUpdate(
            { orderId: order._id },
            { hash: fileHash, orderId: order._id },
            { upsert: true, new: true }
        );
        await AdminNotification.create({
            message: `Proof re-uploaded for order #${order._id.toString().slice(-6)} by ${req.user.name}`,
            type: 'info', orderId: order._id,
        });
        res.json({ success: true, message: 'Proof uploaded. Order is back in Processing.' });
    } catch (e) {
        console.error('Re-upload error:', e.message);
        res.status(500).json({ message: 'Re-upload failed.' });
    }
});

// ─────────────────────────────────────────────
//  INVOICE (printable HTML)
// ─────────────────────────────────────────────
app.get('/api/orders/:id/invoice', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id).lean();
        if (!order) return res.status(404).send('Order not found.');
        if (order.userId.toString() !== req.user.id) return res.status(403).send('Access denied.');

        const fmt  = n => Number(n).toLocaleString('en-IN');
        const rows = order.items.map(i => `
            <tr>
                <td>${i.name || '—'}</td>
                <td>${i.type || '—'}</td>
                <td>${i.breed || '—'}</td>
                <td>${i.weight ? i.weight + ' kg' : '—'}</td>
                <td style="text-align:right">₹${fmt(i.price)}</td>
            </tr>`).join('');

        res.send(`<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Invoice – LivestockMart</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:Arial,sans-serif;color:#222;padding:40px;max-width:800px;margin:auto}
  .logo{color:#166534;font-size:26px;font-weight:800;letter-spacing:-1px}
  .header{display:flex;justify-content:space-between;border-bottom:3px solid #22c55e;padding-bottom:18px;margin-bottom:24px}
  .section{display:flex;justify-content:space-between;margin-bottom:32px;gap:20px}
  .box{flex:1;background:#f9fafb;padding:16px;border-radius:8px;font-size:13px;line-height:1.7}
  .box strong{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;margin-bottom:4px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f0fdf4;text-align:left;padding:10px 12px;border-bottom:2px solid #d1d5db;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
  td{padding:10px 12px;border-bottom:1px solid #e5e7eb}
  .total-row{text-align:right;padding:16px 0;font-size:18px;font-weight:800;color:#166534}
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600;background:#dcfce7;color:#166534}
  .footer{margin-top:48px;text-align:center;font-size:11px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:16px}
  @media print{body{padding:20px}.no-print{display:none}}
</style></head><body>
<div class="header">
  <div>
    <div class="logo">🐐 LivestockMart</div>
    <div style="font-size:12px;color:#6b7280;margin-top:4px">India's Premier Livestock Marketplace</div>
  </div>
  <div style="text-align:right;font-size:13px">
    <div style="font-size:18px;font-weight:700;color:#111">Invoice</div>
    <div style="color:#6b7280">#${order._id.toString().slice(-8).toUpperCase()}</div>
    <div style="margin-top:4px">${order.date}</div>
    <div style="margin-top:6px"><span class="badge">${order.status}</span></div>
  </div>
</div>
<div class="section">
  <div class="box">
    <strong>Billed To</strong>
    ${order.address?.name || '—'}<br>
    ${order.address?.line1 || ''}<br>
    ${order.address?.line2 ? order.address.line2 + '<br>' : ''}
    ${order.address?.city || ''}, ${order.address?.state || ''} – ${order.address?.pincode || ''}<br>
    📞 +91 ${order.address?.phone || ''}
  </div>
  <div class="box">
    <strong>Order Info</strong>
    Customer: ${order.customer}<br>
    Items: ${order.items.length}<br>
    Payment: UPI
  </div>
</div>
<table>
  <thead><tr><th>Item</th><th>Type</th><th>Breed</th><th>Weight</th><th style="text-align:right">Price</th></tr></thead>
  <tbody>${rows}</tbody>
</table>
<div class="total-row">Grand Total: ₹${fmt(order.total)}</div>
<div class="footer">
  Thank you for shopping at LivestockMart.<br>
  Door No: 3-73/1, Near Z.P. High School, K. Pentapadu, West Godavari, AP – 534166<br>
  📞 9000274439 &nbsp;|&nbsp; 9908817975
</div>
<script>setTimeout(()=>window.print(),300)</script>
</body></html>`);
    } catch (e) { res.status(500).send('Error generating invoice.'); }
});

// ─────────────────────────────────────────────
//  PAYMENT
// ─────────────────────────────────────────────
app.post('/api/payment/create', authMiddleware, (req, res) => {
    const amount    = parseFloat(req.body.amount) || 0;
    const paymentId = 'PAY_' + Date.now() + '_' + req.user.id.slice(-6);
    const upiString = `upi://pay?pa=${UPI_ID}&pn=LivestockMart&am=${amount}&cu=INR&tn=LivestockOrder`;
    res.json({ upiString, paymentId, amount });
});

app.post('/api/payment/confirm', authMiddleware, (req, res) => {
    // Confirmation is handled by the order creation (proof upload).
    // This endpoint just signals the client to proceed to upload.
    res.json({ success: true, message: 'Proceed to create order with payment proof.' });
});

// ─────────────────────────────────────────────
//  STATIC PAGE ROUTES
// ─────────────────────────────────────────────
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Catch-all — return index.html for client-side routes
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) return res.status(404).json({ message: 'API route not found.' });
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.message);
    if (err.name === 'MulterError') {
        return res.status(400).json({ message: `File upload error: ${err.message}` });
    }
    res.status(500).json({ error: 'An unexpected error occurred. Please try again.' });
});

// ─────────────────────────────────────────────
//  START
// ─────────────────────────────────────────────
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 LivestockMart server running on http://localhost:${PORT}`);
        console.log(`   Environment : ${IS_PROD ? 'production' : 'development'}`);
        console.log(`   Session TTL  : ${SESSION_HOURS}h`);
    });
}

module.exports = app;
