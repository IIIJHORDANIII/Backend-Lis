const mongoose = require('mongoose');

const draftSaleSchema = new mongoose.Schema({
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
      min: 1
    }
  }],
  total: {
    type: Number,
    default: 0
  },
  commission: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

// Índice único para garantir que cada usuário tenha apenas um rascunho
draftSaleSchema.index({ userId: 1 }, { unique: true });

const DraftSale = mongoose.model('DraftSale', draftSaleSchema);

module.exports = DraftSale;