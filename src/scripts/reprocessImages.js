const AWS = require('aws-sdk');
const mongoose = require('mongoose');
const config = require('../config/config');
const Product = require('../models/Product');
const { processImageTo9x16 } = require('../services/imageProcessor');
const { s3 } = require('../services/s3Service');

// Configure AWS
const s3Client = new AWS.S3({
  accessKeyId: config.aws.accessKeyId,
  secretAccessKey: config.aws.secretAccessKey,
  region: config.aws.region
});

// Connect to MongoDB
mongoose.connect(config.mongodb.uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

/**
 * Baixa uma imagem do S3
 * @param {string} imageUrl - URL da imagem no S3
 * @returns {Promise<Buffer>} - Buffer da imagem
 */
const downloadImageFromS3 = async (imageUrl) => {
  try {
    // Extract the key from the S3 URL
    const url = new URL(imageUrl);
    const key = url.pathname.substring(1); // Remove leading slash
    
    const params = {
      Bucket: config.aws.bucketName,
      Key: key
    };

    const result = await s3Client.getObject(params).promise();
    return result.Body;
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

    const result = await s3Client.upload(params).promise();
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

    await s3Client.deleteObject(params).promise();
    console.log(`Imagem antiga deletada: ${key}`);
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
    console.log(`📥 Baixando imagem: ${product.image}`);
    
    // Baixar imagem do S3
    const imageBuffer = await downloadImageFromS3(product.image);
    console.log(`✅ Imagem baixada (${imageBuffer.length} bytes)`);
    
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
      await new Promise(resolve => setTimeout(resolve, 1000));
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