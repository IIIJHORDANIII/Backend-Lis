const mongoose = require('mongoose');

const condicionalSchema = new mongoose.Schema({
  sellerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  clientName: {
    type: String,
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
    },
    price: {
      type: Number,
      required: true
    }
  }],
  totalOriginal: {
    type: Number,
    required: true
  },
  discount: {
    type: Number,
    default: 0
  },
  totalWithDiscount: {
    type: Number,
    required: true
  },
  status: {
    type: String,
    enum: ['aberto', 'fechado', 'excluido'],
    default: 'aberto'
  },
  notes: {
    type: String,
    default: ''
  },
  closedAt: {
    type: Date,
    default: null
  },
  saleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Sale',
    default: null
  }
}, {
  timestamps: true
});

// Índices para melhorar performance
condicionalSchema.index({ sellerId: 1, status: 1 });
condicionalSchema.index({ status: 1 });
condicionalSchema.index({ createdAt: -1 });

// Middleware para calcular totais automaticamente
condicionalSchema.pre('save', function(next) {
  if (this.products && this.products.length > 0) {
    this.totalOriginal = this.products.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    this.totalWithDiscount = this.totalOriginal - this.discount;
  }
  next();
});

// Método para fechar o condicional
condicionalSchema.methods.close = function(saleId) {
  this.status = 'fechado';
  this.closedAt = new Date();
  this.saleId = saleId;
  return this.save();
};

// Método para excluir o condicional
condicionalSchema.methods.delete = function() {
  this.status = 'excluido';
  return this.save();
};

const Condicional = mongoose.model('Condicional', condicionalSchema);

module.exports = Condicional; 