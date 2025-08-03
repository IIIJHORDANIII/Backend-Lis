require('dotenv').config();
const mongoose = require('mongoose');
const CustomList = require('../models/CustomList');

// Conectar ao MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ Connected to MongoDB Atlas successfully');
}).catch((error) => {
  console.error('❌ Error connecting to MongoDB:', error);
  process.exit(1);
});

const initializeStock = async () => {
  try {
    console.log('🔄 Iniciando inicialização do estoque das listas customizadas...');
    
    const lists = await CustomList.find();
    console.log(`📋 Encontradas ${lists.length} listas para processar`);
    
    let updatedCount = 0;
    
    for (const list of lists) {
      let needsUpdate = false;
      
      for (const product of list.products) {
        if (product.availableQuantity === undefined) {
          product.availableQuantity = product.quantity;
          needsUpdate = true;
          console.log(`  ✅ Produto ${product.productId} na lista "${list.name}": estoque inicializado com ${product.quantity} unidades`);
        }
      }
      
      if (needsUpdate) {
        await list.save();
        updatedCount++;
        console.log(`  📝 Lista "${list.name}" atualizada`);
      }
    }
    
    console.log(`\n🎉 Processo concluído!`);
    console.log(`📊 ${updatedCount} listas foram atualizadas`);
    console.log(`📊 ${lists.length - updatedCount} listas já estavam atualizadas`);
    
    // Verificar listas esgotadas
    const outOfStockLists = await CustomList.find({ isOutOfStock: true });
    console.log(`⚠️  ${outOfStockLists.length} listas estão marcadas como esgotadas`);
    
    if (outOfStockLists.length > 0) {
      console.log('\n📋 Listas esgotadas:');
      outOfStockLists.forEach(list => {
        console.log(`  - ${list.name} (ID: ${list._id})`);
      });
    }
    
  } catch (error) {
    console.error('❌ Erro durante a inicialização:', error);
  } finally {
    mongoose.connection.close();
    console.log('🔌 Conexão com MongoDB fechada');
  }
};

// Executar o script
initializeStock(); 