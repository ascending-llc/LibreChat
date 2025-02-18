const { S3Client } = require('@aws-sdk/client-s3');
const { fromNodeProviderChain } = require('@aws-sdk/credential-providers');
const { logger } = require('~/config');

let i = 0;
let s3 = null;

const initializeS3 = () => {
  // Return existing instance if already initialized
  if (s3) {
    return s3;
  }

  const s3Config = {
    region: process.env.AWS_REGION,
    credentials: fromNodeProviderChain(),
  };

  if (!s3Config.region || !s3Config.credentials) {
    logger.info('[Optional] S3 not initialized due to missing configuration.');
    return null;
  }

  s3 = new S3Client(s3Config);
  logger.info('S3 initialized with AWS SDK v3');
  return s3;
};

module.exports = { initializeS3 };
