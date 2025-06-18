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

module.exports = {
  uploadToS3
}; 