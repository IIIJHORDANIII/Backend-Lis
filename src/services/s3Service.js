const AWS = require('aws-sdk');
const config = require('../config/config');

const s3 = new AWS.S3({
  accessKeyId: config.aws.accessKeyId,
  secretAccessKey: config.aws.secretAccessKey,
  region: config.aws.region
});

const uploadToS3 = async (file) => {
  if (!file || !file.buffer) {
    throw new Error('No file or file buffer provided');
  }

  const params = {
    Bucket: config.aws.bucketName,
    Key: `products/${Date.now()}-${file.originalname}`,
    Body: file.buffer,
    ContentType: file.mimetype,
    ACL: 'public-read'
  };

  try {
    const result = await s3.upload(params).promise();
    return result.Location;
  } catch (error) {
    console.error('Error uploading to S3:', error);
    throw new Error('Failed to upload image to S3');
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
  extractS3Key
}; 