const mongoose = require('mongoose');
const { deleteFromS3 } = require('../services/s3Service');

const productSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true
  },
  commission: {
    type: Number,
    required: true,
    default: 0
  },
  quantity: {
    type: Number,
    required: true,
    default: 0
  },
  category: {
    type: String,
    enum: ['masculino', 'feminino', 'infantil'],
    required: true
  },
  image: {
    type: String,
    required: true
  }
}, { timestamps: true });

// Middleware to delete image from S3 when product is deleted
productSchema.pre('deleteOne', { document: true, query: false }, async function(next) {
  try {
    if (this.image) {
      await deleteFromS3(this.image);
    }
    next();
  } catch (error) {
    console.error('Error deleting image from S3 in middleware:', error);
    next(); // Continue with deletion even if S3 deletion fails
  }
});

// Middleware for deleteMany operations
productSchema.pre('deleteMany', async function(next) {
  try {
    const products = await this.model.find(this.getQuery());
    for (const product of products) {
      if (product.image) {
        await deleteFromS3(product.image);
      }
    }
    next();
  } catch (error) {
    console.error('Error deleting images from S3 in deleteMany middleware:', error);
    next(); // Continue with deletion even if S3 deletion fails
  }
});

module.exports = mongoose.model('Product', productSchema); 