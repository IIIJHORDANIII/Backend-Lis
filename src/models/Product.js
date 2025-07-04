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
  costPrice: {
    type: Number,
    required: true
  },
  finalPrice: {
    type: Number,
    required: true
  },
  commission: {
    type: Number,
    required: true
  },
  profit: {
    type: Number,
    required: true
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

// Middleware para calcular preços automaticamente antes de salvar
productSchema.pre('save', function(next) {
  // Sempre calcular os valores se costPrice estiver presente
  if (this.costPrice) {
    // Fórmula: PreçoVenda = (PreçoCusto * 2) / 0.70
    this.finalPrice = (this.costPrice * 2) / 0.70;
    
    // Comissão fixa de 30%
    this.commission = this.finalPrice * 0.30;
    
    // Lucro = Preço Final - Preço Custo - Comissão
    this.profit = this.finalPrice - this.costPrice - this.commission;
  }
  next();
});

// Middleware de validação para garantir que os campos calculados existam
productSchema.pre('validate', function(next) {
  if (this.costPrice && !this.finalPrice) {
    // Fórmula: PreçoVenda = (PreçoCusto * 2) / 0.70
    this.finalPrice = (this.costPrice * 2) / 0.70;
  }
  
  if (this.finalPrice && !this.commission) {
    // Comissão fixa de 30%
    this.commission = this.finalPrice * 0.30;
  }
  
  if (this.finalPrice && this.costPrice && this.commission && !this.profit) {
    // Lucro = Preço Final - Preço Custo - Comissão
    this.profit = this.finalPrice - this.costPrice - this.commission;
  }
  
  next();
});

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