const mongoose = require('mongoose');

const customListSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    default: ''
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  products: [{
    productId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    quantity: {
      type: Number,
      required: true,
      default: 1
    },
    availableQuantity: {
      type: Number,
      required: true,
      default: 1
    }
  }],
  sharedWith: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  isPublic: {
    type: Boolean,
    default: false
  },
  isOutOfStock: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

// Middleware para calcular se a lista está esgotada
customListSchema.pre('save', function(next) {
  if (this.products && this.products.length > 0) {
    const totalAvailable = this.products.reduce((sum, item) => sum + (item.availableQuantity || 0), 0);
    this.isOutOfStock = totalAvailable === 0;
  }
  next();
});

// Método para atualizar estoque disponível
customListSchema.methods.updateStock = function(productId, soldQuantity) {
  const product = this.products.find(p => p.productId.toString() === productId.toString());
  if (product) {
    product.availableQuantity = Math.max(0, product.availableQuantity - soldQuantity);
    this.isOutOfStock = this.products.every(p => p.availableQuantity === 0);
  }
  return this.save();
};

// Método para verificar se um produto está disponível
customListSchema.methods.isProductAvailable = function(productId, requestedQuantity) {
  const product = this.products.find(p => p.productId.toString() === productId.toString());
  return product && product.availableQuantity >= requestedQuantity;
};

module.exports = mongoose.model('CustomList', customListSchema); 