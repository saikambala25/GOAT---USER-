const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto'); // Used for checking duplicate proofs
require('dotenv').config();

// Models
const Livestock = require('./models/Livestock');
const Order = require('./models/Order');
const User = require('./models/User');

// --- INTERNAL MODELS ---
// 1. ProofHash: To prevent duplicate image uploads
const proofHashSchema = new mongoose.Schema({
    hash: { type: String, required: true, unique: true },
    orderId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'Order' },
    createdAt: { type: Date, default: Date.now }
});
const ProofHash = mongoose.models.ProofHash || mongoose.model('ProofHash', proofHashSchema);

// 2. AdminNotification: To notify admin dashboard
const adminNotifSchema = new mongoose.Schema({
    message: String,
    type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
    orderId: mongoose.Schema.Types.ObjectId,
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});
const AdminNotification = mongoose.models.AdminNotification || mongoose.model('AdminNotification', adminNotifSchema);
// -----------------------

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key-123';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/livestockmart';

// --- SERVERLESS MONGODB CONNECTION ---
let cached = global.mongoose;
if (!cached) { cached = global.mongoose = { conn: null, promise: null }; }

async function connectDB() {
    if (cached.conn) return cached.conn;
    if (!cached.promise) {
        const opts = { bufferCommands: false, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 };
        cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => {
            console.log('âœ… New MongoDB Connection Established');
            return mongoose;
        });
    }
    try { cached.conn = await cached.promise; } catch (e) { cached.promise = null; throw e; }
    return cached.conn;
}

app.use(async (req, res, next) => {
    try { await connectDB(); next(); } 
    catch (error) { console.error("âŒ DB Error:", error); res.status(500).json({ error: "Database connection failed" }); }
});
// -------------------------------------

const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } 
});

app.use(cors({ origin: true, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', uptime: process.uptime(), database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected' });
});

// --- HELPER FUNCTIONS ---
function createToken(user) {
    return jwt.sign({ id: user._id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30m' });
}

function setAuthCookie(res, token) {
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 60 * 1000 });
}

function authMiddleware(req, res, next) {
    const token = req.cookies && req.cookies.token;
    if (!token) return res.status(401).json({ message: 'Not authenticated' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = { id: decoded.id, email: decoded.email, name: decoded.name };
        next();
    } catch (err) { return res.status(401).json({ message: 'Invalid or expired token' }); }
}

function getFileHash(buffer) {
    return crypto.createHash('md5').update(buffer).digest('hex');
}

// --- â³ AUTO-EXPIRE UNPAID LOCKS ---
async function expireUnpaidOrders() {
    try {
        const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
        
        // Find Pending orders older than 30 mins
        const expiredOrders = await Order.find({
            status: 'Pending',
            createdAt: { $lt: thirtyMinutesAgo }
        });

        if (expiredOrders.length > 0) {
            console.log(`â³ Found ${expiredOrders.length} expired orders. cleaning up...`);
            
            for (const order of expiredOrders) {
                // 1. Mark Order as Cancelled
                order.status = 'Cancelled';
                await order.save();

                // 2. Release Livestock
                const itemIds = order.items.map(item => item._id);
                await Livestock.updateMany(
                    { _id: { $in: itemIds } },
                    { $set: { status: 'Available' } }
                );

                // 3. Notify Admin
                await AdminNotification.create({
                    message: `System: Order #${order._id.toString().slice(-6)} auto-expired (unpaid > 30m).`,
                    type: 'warning',
                    orderId: order._id
                });
            }
        }
    } catch (err) {
        console.error("Auto-Expire Error:", err);
    }
}
// Run expiration check every 60 seconds
setInterval(expireUnpaidOrders, 60 * 1000); 

// --- AUTH ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ message: 'Email already exists' });
        const newUser = new User({ name, email, password });
        await newUser.save();
        const token = createToken(newUser);
        setAuthCookie(res, token);
        res.status(201).json({ user: { id: newUser._id, name: newUser.name, email: newUser.email } });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Credentials required' });
        const user = await User.findOne({ email });
        if (!user || !(await user.comparePassword(password))) return res.status(400).json({ message: 'Invalid credentials' });
        const token = createToken(user);
        setAuthCookie(res, token);
        res.json({ user: { id: user._id, name: user.name, email: user.email } });
    } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => res.json({ user: req.user }));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ message: 'Logged out' }); });

// --- USER STATE ---
app.get('/api/user/state', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ cart: user.cart || [], wishlist: user.wishlist || [], addresses: user.addresses || [], notifications: user.notifications || [] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/user/state', authMiddleware, async (req, res) => {
    try {
        const { cart, wishlist, addresses, notifications } = req.body;
        const updatedUser = await User.findByIdAndUpdate(req.user.id, { $set: { cart, wishlist, addresses, notifications } }, { new: true });
        res.json({ message: 'State synchronized', success: true });
    } catch (err) { res.status(400).json({ error: 'Failed to save state' }); }
});

// --- LIVESTOCK ---
app.get('/api/livestock', async (req, res) => {
    try { const livestock = await Livestock.find({}, '-image'); res.json(livestock); } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/livestock/image/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        const livestock = await Livestock.findById(req.params.id, 'image');
        if (!livestock?.image?.data) return res.status(404).send('Image not found');
        res.set('Content-Type', livestock.image.contentType);
        res.send(livestock.image.data);
    } catch (err) { res.status(500).send('Server Error'); }
});

// New endpoint to get specific image from images array
app.get('/api/livestock/image/:id/:index', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(404).send('Invalid ID');
        const index = parseInt(req.params.index);
        const livestock = await Livestock.findById(req.params.id, 'images');
        if (!livestock?.images || !livestock.images[index]?.data) return res.status(404).send('Image not found');
        res.set('Content-Type', livestock.images[index].contentType);
        res.send(livestock.images[index].data);
    } catch (err) { res.status(500).send('Server Error'); }
});

// --- ADMIN ROUTES ---
app.get('/api/admin/livestock', async (req, res) => {
    try { const livestock = await Livestock.find({}, '-image').sort({ createdAt: -1 }); res.json({ livestock }); } catch (err) { res.status(500).json({ message: 'Failed', error: err.message }); }
});

// ðŸŸ¢ FIX APPLIED HERE: Added 'age' extraction and multiple images support
app.post('/api/admin/livestock', upload.array('images', 10), async (req, res) => {
    try {
        // Extract all necessary fields, including 'age' which was missing before
        const { name, type, breed, price, tags, status, weight, age } = req.body;

        // Handle multiple images
        let images = [];
        if (req.files && req.files.length > 0) {
            images = req.files.map(file => ({
                data: file.buffer,
                contentType: file.mimetype
            }));
        }

        // Backward compatibility: use first image as main image
        const image = images.length > 0 ? images[0] : undefined;

        let tagArray = tags && typeof tags === 'string' ? tags.split(',') : [];

        // Construct new item including 'age' and multiple images
        // If 'age' is not provided, we try to derive it from 'weight' as a fallback string
        const newItem = new Livestock({
            name,
            type,
            breed,
            age: age || (weight ? `${weight} kg` : "N/A"),
            weight: weight || "N/A",
            price: parseFloat(price) || 0,
            tags: tagArray,
            status: status || 'Available',
            image,
            images
        });

        await newItem.save();
        res.status(201).json(newItem);
    } catch (err) {
        console.error("Livestock Create Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/livestock/:id', upload.array('images', 10), async (req, res) => {
    try {
        const updates = { ...req.body };
        if (updates.price) updates.price = parseFloat(updates.price);

        // Handle multiple images if uploaded
        if (req.files && req.files.length > 0) {
            updates.images = req.files.map(file => ({
                data: file.buffer,
                contentType: file.mimetype
            }));
            // Backward compatibility: use first image as main image
            updates.image = updates.images[0];
        }

        const livestock = await Livestock.findByIdAndUpdate(req.params.id, updates, { new: true });
        res.json(livestock);
    } catch (err) { res.status(500).json({ message: 'Update failed', error: err.message }); }
});

app.delete('/api/admin/livestock/:id', async (req, res) => {
    try { await Livestock.findByIdAndDelete(req.params.id); res.status(204).send(); } catch (err) { res.status(500).json({ message: 'Delete failed', error: err.message }); }
});

app.get('/api/admin/orders', async (req, res) => {
    try {
        // Trigger lazy cleanup on fetch to ensure admin sees up-to-date states
        await expireUnpaidOrders();
        // Exclude image data for performance
        const orders = await Order.find({}, '-paymentProof.data').sort({ createdAt: -1 });
        res.json({ orders });
    } catch (err) { res.status(500).json({ message: 'Failed to load orders', error: err.message }); }
});

app.get('/api/admin/orders/proof/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order?.paymentProof?.data) return res.status(404).send('No proof found');
        res.set('Content-Type', order.paymentProof.contentType);
        res.send(order.paymentProof.data);
    } catch (err) { res.status(500).send('Server Error'); }
});

// âœ… Reject Payment & Restock Items
app.put('/api/admin/orders/:id/reject', async (req, res) => {
    try {
        const { reason } = req.body;
        
        // 1. Update Order Status
        const order = await Order.findByIdAndUpdate(
            req.params.id, 
            { 
                status: 'Payment Rejected', 
                rejectionReason: reason || 'Invalid payment proof.'
            }, 
            { new: true }
        );
        
        if (!order) return res.status(404).json({ message: 'Order not found' });

        // 2. ðŸŸ¢ RESTOCK LOGIC: Set status back to 'Available' for all items in order
        const itemIds = order.items.map(item => item._id);
        if (itemIds.length > 0) {
            await Livestock.updateMany(
                { _id: { $in: itemIds } }, 
                { $set: { status: 'Available' } }
            );
        }

        // 3. Notify User
        await User.findByIdAndUpdate(order.userId, { 
            $push: { notifications: {
                id: 'rej_' + Date.now(), 
                title: 'Order Cancelled', 
                message: `Order #${order._id.toString().slice(-6)} rejected: ${reason}. Items have been restocked.`,
                icon: 'x-circle', 
                color: 'red', 
                timestamp: Date.now(), 
                seen: false
            }}
        });

        res.json({ success: true, message: 'Order rejected and items returned to stock' });
    } catch (err) { 
        console.error("Reject Error:", err);
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/admin/orders/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        res.json(order);
    } catch (err) { res.status(500).json({ message: 'Update failed', error: err.message }); }
});

app.get('/api/admin/users', async (req, res) => {
    try { const users = await User.find({}, 'name email createdAt').sort({ createdAt: -1 }); res.json({ users }); } catch (err) { res.status(500).json({ message: 'Failed to load users', error: err.message }); }
});

// --- NEW: Admin Notifications Endpoint ---
app.get('/api/admin/notifications', async (req, res) => {
    try {
        const notifs = await AdminNotification.find().sort({ createdAt: -1 }).limit(50);
        res.json({ notifications: notifs });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/admin/notifications/clear', async (req, res) => {
    try { await AdminNotification.deleteMany({}); res.json({ success: true }); } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ORDER ROUTES ---
app.get('/api/orders', authMiddleware, async (req, res) => {
    try { const orders = await Order.find({ userId: req.user.id }, '-paymentProof.data').sort({ createdAt: -1 }); res.json(orders); } catch (err) { res.status(500).json({ error: err.message }); }
});

// RE-UPLOAD PROOF (With Duplicate Check & Admin Notif)
app.put('/api/orders/:id/reupload', authMiddleware, upload.single('paymentProof'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).send('No file uploaded');

        // ðŸ”’ DUPLICATE CHECK
        const fileHash = getFileHash(req.file.buffer);
        const existingProof = await ProofHash.findOne({ hash: fileHash });
        if (existingProof && existingProof.orderId.toString() !== req.params.id) {
            return res.status(400).json({ message: 'Duplicate proof detected! This image has already been used.' });
        }

        const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
        if (!order) return res.status(404).json({ message: 'Order not found' });

        await Order.findByIdAndUpdate(req.params.id, {
            status: 'Processing',
            rejectionReason: '',
            paymentProof: { data: req.file.buffer, contentType: req.file.mimetype }
        });

        await ProofHash.findOneAndUpdate(
            { orderId: order._id }, 
            { hash: fileHash, orderId: order._id }, 
            { upsert: true, new: true }
        );

        // ðŸ”” NOTIFY ADMIN
        await AdminNotification.create({
            message: `Proof Re-uploaded for Order #${order._id.toString().slice(-6)} by ${req.user.name}`,
            type: 'info',
            orderId: order._id
        });
        
        res.json({ success: true, message: 'Proof re-uploaded successfully' });
    } catch (err) {
        console.error("Re-upload Error:", err);
        res.status(500).json({ message: 'Re-upload failed' });
    }
});

// CREATE ORDER (With Duplicate Check & Admin Notif)
app.post('/api/orders', authMiddleware, upload.single('paymentProof'), async (req, res) => {
    try {
        const items = req.body.items ? JSON.parse(req.body.items) : [];
        const address = req.body.address ? JSON.parse(req.body.address) : {};
        const total = req.body.total;
        const date = req.body.date;

        let paymentProof;
        let fileHash;

        if (req.file) {
            // ðŸ”’ DUPLICATE CHECK
            fileHash = getFileHash(req.file.buffer);
            const existingProof = await ProofHash.findOne({ hash: fileHash });
            if (existingProof) {
                return res.status(400).json({ message: 'Duplicate proof detected! This image has already been used.' });
            }
            paymentProof = { data: req.file.buffer, contentType: req.file.mimetype };
        }

        const newOrder = new Order({ items, address, total, date, paymentProof, userId: req.user.id, customer: req.user.name });
        await newOrder.save();

        if (fileHash) {
            await ProofHash.create({ hash: fileHash, orderId: newOrder._id });
             // ðŸ”” NOTIFY ADMIN
            await AdminNotification.create({
                message: `New Order #${newOrder._id.toString().slice(-6)} Created with Proof`,
                type: 'success',
                orderId: newOrder._id
            });
        }

        const itemIds = items.map(item => item._id);
        if (itemIds.length > 0) {
            await Livestock.updateMany({ _id: { $in: itemIds } }, { $set: { status: 'Sold' } });
        }
        await User.findByIdAndUpdate(req.user.id, { $set: { cart: [] } });
        
        res.status(201).json(newOrder);
    } catch (err) {
        console.error("Order Create Error:", err);
        res.status(500).json({ error: 'Order creation failed' });
    }
});

app.put('/api/orders/:id/cancel', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
        if (!order) return res.status(404).json({ message: 'Order not found' });
        if (order.status !== 'Processing' && order.status !== 'Pending') return res.status(400).json({ message: 'Cannot cancel order' });

        order.status = 'Cancelled';
        await order.save();
        const itemIds = order.items.map(item => item._id);
        if (itemIds.length > 0) {
            await Livestock.updateMany({ _id: { $in: itemIds } }, { $set: { status: 'Available' } });
        }
        
        // Remove hash so proof can be reused if order is cancelled
        await ProofHash.findOneAndDelete({ orderId: order._id });

        res.json({ success: true, message: 'Order cancelled & items restocked' });
    } catch (err) {
        console.error('Cancel Error:', err);
        res.status(500).json({ message: 'Cancellation failed' });
    }
});


// --- INVOICE ROUTE ---
app.get('/api/orders/:id/invoice', authMiddleware, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) return res.status(404).send('Order not found');

        // Security check: only the owner or an admin can see the invoice
        // (Assuming req.user is populated by authMiddleware)
        if (order.userId.toString() !== req.user.id) {
             return res.status(403).send('Access denied');
        }

        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; padding: 40px; color: #333; }
                .header { display: flex; justify-content: space-between; border-bottom: 2px solid #22c55e; padding-bottom: 20px; }
                .title { color: #166534; font-size: 28px; font-weight: bold; }
                .info { margin-top: 30px; display: flex; justify-content: space-between; }
                table { width: 100%; border-collapse: collapse; margin-top: 40px; }
                th { background-color: #f0fdf4; text-align: left; padding: 12px; border-bottom: 2px solid #ddd; }
                td { padding: 12px; border-bottom: 1px solid #eee; }
                .total { text-align: right; font-size: 20px; font-weight: bold; margin-top: 30px; color: #166534; }
                .footer { margin-top: 50px; text-align: center; color: #888; font-size: 12px; }
            </style>
        </head>
        <body>
            <div class="header">
                <div>
                    <div class="title">LIVESTOCK MART</div>
                    <div>Digital Marketplace for Breeders</div>
                </div>
                <div style="text-align: right">
                    <div><strong>Invoice #:</strong> ${order._id.toString().slice(-6).toUpperCase()}</div>
                    <div><strong>Date:</strong> ${order.date}</div>
                </div>
            </div>

            <div class="info">
                <div>
                    <strong>Billed To:</strong><br>
                    ${order.address.name}<br>
                    ${order.address.line1}<br>
                    ${order.address.city}, ${order.address.state} - ${order.address.pincode}<br>
                    Phone: +91 ${order.address.phone}
                </div>
                <div style="text-align: right">
                    <strong>Status:</strong> ${order.status}
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Item Description</th>
                        <th>Breed</th>
                        <th>Type</th>
                        <th style="text-align: right">Price</th>
                    </tr>
                </thead>
                <tbody>
                    ${order.items.map(item => `
                        <tr>
                            <td>${item.name}</td>
                            <td>${item.breed}</td>
                            <td>${item.type}</td>
                            <td style="text-align: right">â‚¹${item.price.toLocaleString('en-IN')}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>

            <div class="total">Grand Total: â‚¹${order.total.toLocaleString('en-IN')}</div>

            <div class="footer">
                Thank you for your purchase from Livestock Mart.<br>
                For support, contact support@livestockmart.com
            </div>
            <script>window.print();</script>
        </body>
        </html>
        `;
        res.send(html);
    } catch (err) {
        res.status(500).send('Error generating invoice');
    }
});
// --- PAYMENT ROUTES ---
app.post('/api/payment/create', authMiddleware, (req, res) => {
    const { amount } = req.body;
    const paymentId = 'PAY_' + Date.now();
    const upiString = `upi://pay?pa=${process.env.UPI_ID || 'sai.kambala@ybl'}&pn=LivestockMart&am=${amount}`;
    res.json({ upiString, paymentId });
});
app.post('/api/payment/confirm', authMiddleware, (req, res) => res.json({ success: true }));

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

if (require.main === module) {
    app.listen(PORT, () => console.log(`ðŸš€ Server running on port ${PORT}`));
}

module.exports = app;
