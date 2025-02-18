import axios from 'axios';
import jwt from 'jsonwebtoken';
import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { SSOOIDCClient, CreateTokenWithIAMCommand } from "@aws-sdk/client-sso-oidc";
import winston from 'winston';
import dotenv from 'dotenv';

dotenv.config();

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.printf(({ timestamp, level, message }) => {
          return `${timestamp} [${level.toUpperCase()}]: ${message}`;
      })
  ),
  transports: [
      new winston.transports.Console(),
      new winston.transports.File({ filename: 'app.log' })
  ]
});

export class TokenManager {
  constructor() {
    this.AWS_REGION = process.env.AWS_REGION || "us-east-1";
    this.SECRET_NAME = "q_business_api_config";
    this.secretsClient = new SecretsManagerClient({ region: this.AWS_REGION });
    this.ssoOidcClient = new SSOOIDCClient({ region: this.AWS_REGION });
  }

  // Retrieve secret from AWS Secrets Manager
  async getSecret() {
    try {
      const command = new GetSecretValueCommand({ SecretId: this.SECRET_NAME });
      const response = await this.secretsClient.send(command);
      return JSON.parse(response.SecretString);
    } catch (error) {
      logger.error(`Error retrieving secret: ${error}`);
      throw new Error("Failed to retrieve secret");
    }
  }

  // Update the secret in Secrets Manager with new values
  async updateSecret(updatedFields) {
    try {
      const currentSecret = await this.getSecret();
      Object.assign(currentSecret, updatedFields);
      
      const command = new PutSecretValueCommand({
        SecretId: this.SECRET_NAME,
        SecretString: JSON.stringify(currentSecret)
      });
      await this.secretsClient.send(command);
    } catch (error) {
      logger.error(`Error updating secret: ${error}`);
      throw new Error("Failed to update secret");
    }
  }

  // Refresh the Azure AD token using the Azure refresh token.
  // Also updates the refresh token if a new one is returned.
  async refreshAzureADToken(refreshToken) {
    try {
      const secretData = await this.getSecret();
      logger.info("Starting Azure AD token refresh");
      
      const tenantId = secretData.AZURE_AD_TENANT_ID;
      const tokenEndpoint = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
      
      const params = new URLSearchParams();
      params.append("grant_type", "refresh_token");
      params.append("client_id", secretData.AZURE_AD_CLIENT_ID);
      params.append("client_secret", secretData.AZURE_AD_CLIENT_SECRET);
      params.append("refresh_token", refreshToken);
      params.append("scope", "openid profile email offline_access");
      
      logger.info("Sending token refresh request to Azure AD...");
      const response = await axios.post(tokenEndpoint, params, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
      });
      
      const newAzureIdToken = response.data.id_token;
      
      // Update refresh token if a new one is provided
      if (response.data.refresh_token) {
        logger.info("Azure AD refresh token updated.");
        await this.updateSecret({ AZURE_REFRESH_TOKEN: response.data.refresh_token });
      }
      
      logger.info("Azure AD token refresh successful");
      return newAzureIdToken;
    } catch (error) {
      logger.error("Error refreshing Azure AD token:", error.response ? error.response.data : error.message);
      throw new Error("Failed to refresh Azure AD token.");
    }
  }

  // Exchange the Azure AD token with AWS Identity Center to obtain an IDC token
  async exchangeTokenWithIdentityCenter(azureIdToken) {
    try {
      logger.info("Exchanging Azure AD token with AWS Identity Center...");
      const secretData = await this.getSecret();
      
      const command = new CreateTokenWithIAMCommand({
        clientId: secretData.IDC_APPLICATION_ID_AZURE,
        grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: azureIdToken,
      });
      
      logger.info("Sending CreateTokenWithIAMCommand to AWS SSO OIDC...");
      const response = await this.ssoOidcClient.send(command);
      
      if (!response || !response.idToken) {
        throw new Error("Failed to exchange token with Identity Center. Response missing idToken.");
      }
      
      logger.info("Token exchanged successfully with Identity Center.");
      return response.idToken;
    } catch (error) {
      logger.error("Error exchanging token with Identity Center:", error);
      throw new Error("Failed to exchange Azure AD token with Identity Center.");
    }
  }

  // Helper to check if a JWT token is expired
  isTokenExpired(token) {
    try {
      const decoded = jwt.decode(token);
      return Date.now() >= decoded.exp * 1000;
    } catch (error) {
      return true;
    }
  }

  /**
   * getValidIDCIdToken:
   * - Returns the stored IDC token if it exists and is valid.
   * - Otherwise, it checks that an Azure AD refresh token is available, uses it to refresh the Azure ID token, 
   *   exchanges that for a new IDC token via AWS Identity Center, updates the secret store, and then returns the new IDC token.
   */
  async getValidIDCIdToken() {
    const secretData = await this.getSecret();
    const idcIdToken = secretData.IDC_TOKEN;
    const azureRefreshToken = secretData.AZURE_AD_REFRESH_TOKEN;
    
    if (idcIdToken && !this.isTokenExpired(idcIdToken)) {
        logger.info("Using valid IDC ID token from Secrets Manager.");
        return idcIdToken;
    }
    
    // If the Azure ID token is missing or expired, refresh it
    if (azureRefreshToken) {
        logger.info("No valid IDC ID token found. Refreshing using Azure refresh token.");
        const newAzureIdToken = await this.refreshAzureADToken(azureRefreshToken);
        const newIdcIdToken = await this.exchangeTokenWithIdentityCenter(newAzureIdToken);
        await this.updateSecret({ IDC_TOKEN: newIdcIdToken });
        return newIdcIdToken;
    }
    throw new Error("No valid IDC ID token and no Azure AD refresh token available.");
  }
}
