const AWS = require('aws-sdk');
const mongoose = require('mongoose');
const config = require('../config/config');
const Product = require('../models/Product');

// Configure AWS
const s3 = new AWS.S3({
  accessKeyId: config.aws.accessKeyId,
  secretAccessKey: config.aws.secretAccessKey,
  region: config.aws.region
});

// Connect to MongoDB
mongoose.connect(config.mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const cleanupS3Images = async () => {
  try {
    console.log('Starting S3 cleanup...');
    
    // Get all products from database
    const products = await Product.find({}, 'image');
    const productImageUrls = new Set(products.map(p => p.image));
    
    console.log(`Found ${products.length} products in database`);
    
    // List all objects in S3 bucket
    const listParams = {
      Bucket: config.aws.bucketName,
      Prefix: 'products/'
    };
    
    let s3Objects = [];
    let continuationToken;
    
    do {
      const listResult = await s3.listObjectsV2({
        ...listParams,
        ContinuationToken: continuationToken
      }).promise();
      
      s3Objects = s3Objects.concat(listResult.Contents || []);
      continuationToken = listResult.NextContinuationToken;
    } while (continuationToken);
    
    console.log(`Found ${s3Objects.length} objects in S3`);
    
    // Find orphaned images (in S3 but not in database)
    const orphanedObjects = s3Objects.filter(obj => {
      const s3Url = `https://${config.aws.bucketName}.s3.${config.aws.region}.amazonaws.com/${obj.Key}`;
      return !productImageUrls.has(s3Url);
    });
    
    console.log(`Found ${orphanedObjects.length} orphaned images`);
    
    if (orphanedObjects.length === 0) {
      console.log('No orphaned images found. Cleanup complete!');
      return;
    }
    
    // Delete orphaned objects
    const deletePromises = orphanedObjects.map(obj => {
      const deleteParams = {
        Bucket: config.aws.bucketName,
        Key: obj.Key
      };
      
      return s3.deleteObject(deleteParams).promise()
        .then(() => {
          console.log(`Deleted: ${obj.Key}`);
          return obj.Key;
        })
        .catch(error => {
          console.error(`Error deleting ${obj.Key}:`, error);
          return null;
        });
    });
    
    const deletedKeys = await Promise.all(deletePromises);
    const successfulDeletions = deletedKeys.filter(key => key !== null);
    
    console.log(`Successfully deleted ${successfulDeletions.length} orphaned images`);
    console.log('S3 cleanup complete!');
    
  } catch (error) {
    console.error('Error during S3 cleanup:', error);
  } finally {
    mongoose.connection.close();
  }
};

// Run cleanup if this script is executed directly
if (require.main === module) {
  cleanupS3Images();
}

module.exports = { cleanupS3Images }; 