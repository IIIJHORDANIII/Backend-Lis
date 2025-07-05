const AWS = require('aws-sdk');
const config = require('../config/config');
const { processImageTo9x16 } = require('./imageProcessor');

// Validate AWS configuration
const validateAWSConfig = () => {
  if (!config.aws.accessKeyId) {
    throw new Error('AWS_ACCESS_KEY_ID is not configured');
  }
  if (!config.aws.secretAccessKey) {
    throw new Error('AWS_SECRET_ACCESS_KEY is not configured');
  }
  if (!config.aws.region) {
    throw new Error('AWS_REGION is not configured');
  }
  if (!config.aws.bucketName) {
    throw new Error('AWS_BUCKET_NAME is not configured');
  }
};

// Initialize S3 with validation
let s3;
try {
  validateAWSConfig();
  s3 = new AWS.S3({
    accessKeyId: config.aws.accessKeyId,
    secretAccessKey: config.aws.secretAccessKey,
    region: config.aws.region
  });
} catch (error) {
  console.error('AWS S3 configuration error:', error.message);
  throw error;
}

const uploadToS3 = async (file) => {
  if (!file || !file.buffer) {
    throw new Error('No file or file buffer provided');
  }

  // Validate file size (5MB limit)
  if (file.size > 5 * 1024 * 1024) {
    throw new Error('File size exceeds 5MB limit');
  }

  // Validate file type
  if (!file.mimetype.startsWith('image/')) {
    throw new Error('Only image files are allowed');
  }

  try {
    // Processar imagem para formato 9:16
    console.log('Processando imagem para formato 9:16...');
    const processedImageBuffer = await processImageTo9x16(file.buffer);
    console.log('Imagem processada com sucesso');

    const params = {
      Bucket: config.aws.bucketName,
      Key: `products/${Date.now()}-${file.originalname}`,
      Body: processedImageBuffer,
      ContentType: 'image/jpeg', // Sempre JPEG após processamento
      ACL: 'public-read'
    };

    const result = await s3.upload(params).promise();
    console.log(`Successfully uploaded processed image to S3: ${result.Location}`);
    return result.Location;
  } catch (error) {
    console.error('Error uploading to S3:', error);
    
    // Provide more specific error messages
    if (error.code === 'AccessDenied') {
      throw new Error('Access denied to S3 bucket. Check AWS credentials and permissions.');
    }
    if (error.code === 'NoSuchBucket') {
      throw new Error('S3 bucket does not exist. Check AWS_BUCKET_NAME configuration.');
    }
    if (error.code === 'InvalidAccessKeyId') {
      throw new Error('Invalid AWS access key. Check AWS_ACCESS_KEY_ID configuration.');
    }
    if (error.code === 'SignatureDoesNotMatch') {
      throw new Error('Invalid AWS secret key. Check AWS_SECRET_ACCESS_KEY configuration.');
    }
    
    throw new Error(`Failed to upload image to S3: ${error.message}`);
  }
};

const deleteFromS3 = async (imageUrl) => {
  if (!imageUrl) {
    console.log('No image URL provided for deletion');
    return;
  }

  try {
    // Extract the key from the S3 URL
    const url = new URL(imageUrl);
    const key = url.pathname.substring(1); // Remove leading slash
    
    const params = {
      Bucket: config.aws.bucketName,
      Key: key
    };

    await s3.deleteObject(params).promise();
    console.log(`Successfully deleted image from S3: ${key}`);
  } catch (error) {
    console.error('Error deleting from S3:', error);
    // Don't throw error to avoid breaking the product deletion
    // Just log it for debugging
  }
};

const extractS3Key = (imageUrl) => {
  if (!imageUrl) return null;
  
  try {
    const url = new URL(imageUrl);
    return url.pathname.substring(1); // Remove leading slash
  } catch (error) {
    console.error('Error extracting S3 key:', error);
    return null;
  }
};

module.exports = {
  uploadToS3,
  deleteFromS3,
  extractS3Key,
  s3
}; 