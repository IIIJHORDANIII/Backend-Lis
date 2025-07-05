const sharp = require('sharp');

/**
 * Processa uma imagem para o formato 9:16 (portrait)
 * @param {Buffer} imageBuffer - Buffer da imagem original
 * @param {number} targetWidth - Largura desejada (padrão: 1080px)
 * @returns {Promise<Buffer>} - Buffer da imagem processada
 */
const processImageTo9x16 = async (imageBuffer, targetWidth = 1080) => {
  try {
    // Calcular altura baseada na proporção 9:16
    const targetHeight = Math.round((targetWidth * 16) / 9);
    
    // Processar a imagem
    const processedImage = await sharp(imageBuffer)
      .resize(targetWidth, targetHeight, {
        fit: 'cover', // Mantém a proporção e corta se necessário
        position: 'center' // Centraliza o corte
      })
      .jpeg({ 
        quality: 85, // Qualidade JPEG
        progressive: true // JPEG progressivo para melhor carregamento
      })
      .toBuffer();
    
    return processedImage;
  } catch (error) {
    console.error('Erro ao processar imagem:', error);
    throw new Error(`Falha ao processar imagem: ${error.message}`);
  }
};

/**
 * Processa uma imagem mantendo a proporção original mas garantindo tamanho máximo
 * @param {Buffer} imageBuffer - Buffer da imagem original
 * @param {number} maxWidth - Largura máxima (padrão: 1080px)
 * @param {number} maxHeight - Altura máxima (padrão: 1920px)
 * @returns {Promise<Buffer>} - Buffer da imagem processada
 */
const processImageWithMaxSize = async (imageBuffer, maxWidth = 1080, maxHeight = 1920) => {
  try {
    // Obter metadados da imagem
    const metadata = await sharp(imageBuffer).metadata();
    
    // Calcular novas dimensões mantendo proporção
    let { width, height } = metadata;
    
    if (width > maxWidth || height > maxHeight) {
      const ratio = Math.min(maxWidth / width, maxHeight / height);
      width = Math.round(width * ratio);
      height = Math.round(height * ratio);
    }
    
    // Processar a imagem
    const processedImage = await sharp(imageBuffer)
      .resize(width, height, {
        fit: 'inside', // Mantém a proporção sem cortar
        withoutEnlargement: true // Não aumenta a imagem se for menor
      })
      .jpeg({ 
        quality: 85,
        progressive: true
      })
      .toBuffer();
    
    return processedImage;
  } catch (error) {
    console.error('Erro ao processar imagem:', error);
    throw new Error(`Falha ao processar imagem: ${error.message}`);
  }
};

/**
 * Detecta se uma imagem está em formato portrait (altura > largura)
 * @param {Buffer} imageBuffer - Buffer da imagem
 * @returns {Promise<boolean>} - true se for portrait, false se for landscape
 */
const isPortrait = async (imageBuffer) => {
  try {
    const metadata = await sharp(imageBuffer).metadata();
    return metadata.height > metadata.width;
  } catch (error) {
    console.error('Erro ao detectar orientação da imagem:', error);
    return false;
  }
};

module.exports = {
  processImageTo9x16,
  processImageWithMaxSize,
  isPortrait
}; 