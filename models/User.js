const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// --- FIX: Relaxed Schema to prevent 500/400 Errors ---
const cartItemSchema = new mongoose.Schema({
    _id: { type: String }, // Kept as String to match frontend ID
    name: { type: String },
    price: { type: Number },
    breed: { type: String },
    type: { type: String }, 
    weight: { type: String }, 
    selected: { type: Boolean, default: true },
}, { _id: false });

const addressSchema = new mongoose.Schema({
    label: { type: String, default: '' },
    name: { type: String },
    line1: { type: String }, 
    line2: { type: String },
    city: { type: String },
    state: { type: String },
    pincode: { type: String },
    phone: { type: String },
}, { _id: false });

const notificationSchema = new mongoose.Schema({
    id: String,
    title: String,
    message: String,
    icon: String,
    color: String,
    timestamp: { type: Number, default: Date.now },
    seen: { type: Boolean, default: false } // <--- NEW: Added for badge logic
}, { _id: false });

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    
    // User State Arrays
    cart: [cartItemSchema], 
    wishlist: [{ type: String }],
    addresses: [addressSchema],
    notifications: [notificationSchema], 
    
    createdAt: { type: Date, default: Date.now },
});

// Password hashing
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) { next(err); }
});

userSchema.methods.comparePassword = function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
