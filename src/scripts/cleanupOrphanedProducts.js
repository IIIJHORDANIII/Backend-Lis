require('dotenv').config();
const mongoose = require('mongoose');
const CustomList = require('../models/CustomList');
const Product = require('../models/Product');

// Conectar ao MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ Connected to MongoDB Atlas successfully');
}).catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

const cleanupOrphanedProducts = async () => {
  try {
    console.log('🔍 Iniciando limpeza de produtos órfãos...');
    
    // Buscar todos os produtos existentes
    const existingProducts = await Product.find({}, '_id');
    const existingProductIds = existingProducts.map(p => p._id.toString());
    
    console.log(`📦 Encontrados ${existingProductIds.length} produtos válidos`);
    
    // Buscar todas as listas
    const lists = await CustomList.find({});
    console.log(`📋 Encontradas ${lists.length} listas`);
    
    let totalCleaned = 0;
    
    for (const list of lists) {
      const originalLength = list.products.length;
      
      // Filtrar apenas produtos que ainda existem
      list.products = list.products.filter(productId => 
        existingProductIds.includes(productId.toString())
      );
      
      const cleanedLength = list.products.length;
      const removedCount = originalLength - cleanedLength;
      
      if (removedCount > 0) {
        console.log(`🧹 Lista "${list.name}": removidos ${removedCount} produtos órfãos`);
        await list.save();
        totalCleaned += removedCount;
      }
    }
    
    console.log(`✅ Limpeza concluída! Total de produtos órfãos removidos: ${totalCleaned}`);
    
  } catch (error) {
    console.error('❌ Erro durante a limpeza:', error);
  } finally {
    mongoose.connection.close();
    console.log('🔌 Conexão com MongoDB fechada');
  }
};

// Executar o script
cleanupOrphanedProducts(); 