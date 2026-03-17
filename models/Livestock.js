const mongoose = require('mongoose');

const livestockSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, required: true }, // Goat or Sheep
    breed: { type: String, required: true },

age: { type: String, required: true },
    age: { type: String, required: true },
    
    // ADDED WEIGHT FIELD HERE
    weight: { type: String, required: true }, 

    price: { type: Number, required: true },
    image: {
        data: { type: Buffer },
        contentType: { type: String }
    }, // Binary image data (optional, for backward compatibility)
    images: [{
        data: { type: Buffer },
        contentType: { type: String }
    }], // Array of images for multi-image support
    tags: [String],
    status: { type: String, default: 'Available' },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Livestock', livestockSchema);
