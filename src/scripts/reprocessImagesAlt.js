const mongoose = require('mongoose');
const config = require('../config/config');
const Product = require('../models/Product');
const { processImageTo9x16 } = require('../services/imageProcessor');
const { s3 } = require('../services/s3Service');
const fetch = require('node-fetch');

// Connect to MongoDB
mongoose.connect(config.mongodb.uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

/**
 * Baixa uma imagem usando fetch (para URLs públicas)
 * @param {string} imageUrl - URL da imagem
 * @returns {Promise<Buffer>} - Buffer da imagem
 */
const downloadImageWithFetch = async (imageUrl) => {
  try {
    console.log(`📥 Baixando imagem via HTTP: ${imageUrl}`);
    const response = await fetch(imageUrl);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    console.log(`✅ Imagem baixada via HTTP (${buffer.length} bytes)`);
    return buffer;
  } catch (error) {
    console.error(`Erro ao baixar imagem ${imageUrl}:`, error);
    throw error;
  }
};

/**
 * Faz upload de uma nova imagem processada para o S3
 * @param {Buffer} imageBuffer - Buffer da imagem processada
 * @param {string} originalKey - Chave original no S3
 * @returns {Promise<string>} - Nova URL da imagem
 */
const uploadProcessedImage = async (imageBuffer, originalKey) => {
  try {
    // Criar nova chave com timestamp para evitar conflitos
    const timestamp = Date.now();
    const keyParts = originalKey.split('/');
    const filename = keyParts[keyParts.length - 1];
    const newKey = `products/processed-${timestamp}-${filename}`;
    
    const params = {
      Bucket: config.aws.bucketName,
      Key: newKey,
      Body: imageBuffer,
      ContentType: 'image/jpeg',
      ACL: 'public-read'
    };

    const result = await s3.upload(params).promise();
    return result.Location;
  } catch (error) {
    console.error(`Erro ao fazer upload da imagem processada:`, error);
    throw error;
  }
};

/**
 * Deleta uma imagem antiga do S3
 * @param {string} imageUrl - URL da imagem a ser deletada
 */
const deleteOldImage = async (imageUrl) => {
  try {
    const url = new URL(imageUrl);
    const key = url.pathname.substring(1);
    
    const params = {
      Bucket: config.aws.bucketName,
      Key: key
    };

    await s3.deleteObject(params).promise();
    console.log(`🗑️  Imagem antiga deletada: ${key}`);
  } catch (error) {
    console.error(`Erro ao deletar imagem antiga ${imageUrl}:`, error);
    // Não falha o processo se não conseguir deletar a imagem antiga
  }
};

/**
 * Reprocessa uma imagem individual
 * @param {Object} product - Produto com a imagem
 * @returns {Promise<boolean>} - true se foi processado com sucesso
 */
const reprocessProductImage = async (product) => {
  try {
    console.log(`\n🔄 Processando imagem do produto: ${product.name}`);
    
    // Baixar imagem usando fetch
    const imageBuffer = await downloadImageWithFetch(product.image);
    
    // Processar imagem para formato 9:16
    console.log(`🖼️  Processando para formato 9:16...`);
    const processedImageBuffer = await processImageTo9x16(imageBuffer);
    console.log(`✅ Imagem processada (${processedImageBuffer.length} bytes)`);
    
    // Extrair chave original para criar nova chave
    const url = new URL(product.image);
    const originalKey = url.pathname.substring(1);
    
    // Fazer upload da nova imagem
    console.log(`📤 Fazendo upload da nova imagem...`);
    const newImageUrl = await uploadProcessedImage(processedImageBuffer, originalKey);
    console.log(`✅ Nova imagem enviada: ${newImageUrl}`);
    
    // Atualizar produto no banco de dados
    product.image = newImageUrl;
    await product.save();
    console.log(`💾 Produto atualizado no banco de dados`);
    
    // Deletar imagem antiga (opcional - comentado para segurança)
    // await deleteOldImage(product.image);
    // console.log(`🗑️  Imagem antiga deletada`);
    
    console.log(`✅ Produto "${product.name}" processado com sucesso!`);
    return true;
    
  } catch (error) {
    console.error(`❌ Erro ao processar produto "${product.name}":`, error.message);
    return false;
  }
};

/**
 * Script principal para reprocessar todas as imagens
 */
const reprocessAllImages = async () => {
  try {
    console.log('🚀 Iniciando reprocessamento de todas as imagens...');
    console.log('📊 Buscando produtos no banco de dados...');
    
    // Buscar todos os produtos com imagens
    const products = await Product.find({ image: { $exists: true, $ne: null } });
    
    if (products.length === 0) {
      console.log('ℹ️  Nenhum produto com imagem encontrado.');
      return;
    }
    
    console.log(`📦 Encontrados ${products.length} produtos com imagens`);
    
    let successCount = 0;
    let errorCount = 0;
    
    // Processar cada produto
    for (let i = 0; i < products.length; i++) {
      const product = products[i];
      console.log(`\n📋 [${i + 1}/${products.length}] Processando produto: ${product.name}`);
      
      const success = await reprocessProductImage(product);
      
      if (success) {
        successCount++;
      } else {
        errorCount++;
      }
      
      // Pequena pausa entre processamentos para não sobrecarregar
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    console.log('\n🎉 Reprocessamento concluído!');
    console.log(`✅ Produtos processados com sucesso: ${successCount}`);
    console.log(`❌ Produtos com erro: ${errorCount}`);
    console.log(`📊 Total de produtos: ${products.length}`);
    
  } catch (error) {
    console.error('❌ Erro durante o reprocessamento:', error);
  } finally {
    // Fechar conexão com MongoDB
    await mongoose.connection.close();
    console.log('🔌 Conexão com MongoDB fechada');
    process.exit(0);
  }
};

// Executar o script
if (require.main === module) {
  reprocessAllImages();
}

module.exports = {
  reprocessAllImages,
  reprocessProductImage
}; 