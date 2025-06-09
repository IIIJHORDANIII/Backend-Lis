const mongoose = require('mongoose');

const saleSchema = new mongoose.Schema({
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
      required: true
      // Removido min: 1 para permitir devoluções (quantidade negativa)
    }
  }],
  total: {
    type: Number,
    required: true
    // Removido min: 0 para permitir devoluções (total negativo)
  },
  commission: {
    type: Number,
    required: true
    // Removido min: 0 para permitir comissão negativa em devoluções
  }
}, {
  timestamps: true
});

// Adicionar índices para melhorar a performance
saleSchema.index({ userId: 1 });
saleSchema.index({ createdAt: -1 });

const Sale = mongoose.model('Sale', saleSchema);

module.exports = Sale;