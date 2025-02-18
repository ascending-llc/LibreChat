import express, { application } from 'express';
import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import axios from 'axios';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { SSOOIDCClient, CreateTokenWithIAMCommand } from "@aws-sdk/client-sso-oidc";
import { QBusinessClient, ChatCommand, ChatSyncCommand } from "@aws-sdk/client-qbusiness";
import winston from 'winston';

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

const app = express();
const PORT = process.env.PORT || 8080;
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const SECRET_NAME = "q_business_api_config";

const secretsClient = new SecretsManagerClient({ region: AWS_REGION });
const stsClient = new STSClient({ region: AWS_REGION });
const ssoOidcClient = new SSOOIDCClient({ region: AWS_REGION });

app.use(express.json());

async function getSecret() {
    try {
        const command = new GetSecretValueCommand({ SecretId: SECRET_NAME });
        const response = await secretsClient.send(command);
        return JSON.parse(response.SecretString);
    } catch (error) {
        logger.error(`Error retrieving secret: ${error}`);
        throw new Error("Failed to retrieve secret");
    }
}

async function refreshCognitoIdToken(refreshToken) {
    try {
        const secretData = await getSecret();
        logger.info("Starting Refresh Cognito ID token");
        
        const tokenEndpoint = `${secretData.COGNITO_DOMAIN}/oauth2/token`;
        const payload = {
            grant_type: "refresh_token",
            client_id: secretData.CLIENT_ID,
            client_secret: secretData.CLIENT_SECRET,
            refresh_token: refreshToken
        };
        
        logger.info("Sending token refresh request...");

        const response = await axios.post(tokenEndpoint, payload, {
            headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });

        logger.info("Token refresh successful");
        return response.data.id_token;
    } catch (error) {
        logger.error("Error refreshing Cognito ID token:", error.response ? error.response.data : error.message);
        throw new Error("Failed to refresh Cognito ID token.");
    }
}


async function exchangeTokenWithIdentityCenter(idToken) {
    try {
        logger.info("Exchanging Cognito ID token with Identity Center...");
        const secretData = await getSecret();
        
        const command = new CreateTokenWithIAMCommand({
            clientId: secretData.IDC_APPLICATION_ID,
            grantType: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion: idToken,
        });
        
        logger.info("Sending CreateTokenCommand to AWS SSO OIDC...");
        const response = await ssoOidcClient.send(command);
        
        if (!response || !response.idToken) {
            throw new Error("Failed to exchange token with Identity Center. Response missing idToken.");
        }
        
        logger.info("Token exchanged successfully with Identity Center.");
        return response.idToken;
    } catch (error) {
        logger.error("Error exchanging token with Identity Center:", error);
        throw new Error("Failed to exchange Cognito ID token with Identity Center.");
    }
}

async function updateSecret(updatedFields) {
    try {
        const currentSecret = await getSecret();
        Object.assign(currentSecret, updatedFields);
        
        const command = new PutSecretValueCommand({
            SecretId: SECRET_NAME,
            SecretString: JSON.stringify(currentSecret)
        });
        await secretsClient.send(command);
    } catch (error) {
        logger.error(`Error updating secret: ${error}`);
        throw new Error("Failed to update secret");
    }
}

async function getValidIDCIdToken() {
    const secretData = await getSecret();
    const idcIdToken = secretData.IDC_TOKEN;
    const cognitoRefreshToken = secretData.COGNITO_REFRESH_TOKEN;

    if (idcIdToken && !isTokenExpired(idcIdToken)) {
        logger.info("Using valid IDC ID token from Secrets Manager.");
        return idcIdToken;
    }

    if (cognitoRefreshToken) {
        logger.info("No valid IDC ID token found. Refreshing Cognito ID token first.")
        const newCognitoIdToken = await refreshCognitoIdToken(cognitoRefreshToken);
        const newIdcIdToken = await exchangeTokenWithIdentityCenter(newCognitoIdToken);
        await updateSecret({ IDC_TOKEN: newIdcIdToken, COGNITO_REFRESH_TOKEN: cognitoRefreshToken });
        return newIdcIdToken;
    }
    throw new Error("No valid IDC ID token and no Cognito refresh token available.");
}

function isTokenExpired(token) {
    try {
        const decoded = jwt.decode(token);
        return Date.now() >= decoded.exp * 1000;
    } catch (error) {
        return true;
    }
}

async function assumeRoleWithToken(iamToken) {
    const secretData = await getSecret();
    const roleArn = secretData.IAM_ROLE;
    const decodedToken = jwt.decode(iamToken);
    const command = new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: "qapp",
        ProvidedContexts: [{
            ProviderArn: "arn:aws:iam::aws:contextProvider/IdentityCenter",
            ContextAssertion: decodedToken["sts:identity_context"]
        }]
    });
    const response = await stsClient.send(command);
    return response.Credentials;
}

app.post("/v1/chat/completions", async (req, res) => {
    try {
        // logger.info("Received request:", JSON.stringify(req.body, null, 2));
        const idcIdToken = await getValidIDCIdToken();
        logger.info("Retrieved IDC ID Token");
        const awsCredentials = await assumeRoleWithToken(idcIdToken);
        logger.info("Assumed role with token");
        
        const secretData = await getSecret();
        logger.info("Retrieved secret data");

        const qBusinessClient = new QBusinessClient({
            region: AWS_REGION,
            credentials: {
                accessKeyId: awsCredentials.AccessKeyId,
                secretAccessKey: awsCredentials.SecretAccessKey,
                sessionToken: awsCredentials.SessionToken
            }
        });
        logger.info("Initialized QBusinessClient");

        const conversationMessages = req.body.messages?.map(msg => ({
            role: msg.role,
            content: msg.content
        })) || [];
        
        logger.info("Processed conversation messages.");
        
        if (!conversationMessages || conversationMessages.length === 0) {
            logger.error("conversationMessages is empty or undefined!");
        }

        const lastMessage = conversationMessages[conversationMessages.length - 1];

        if (lastMessage.role === "system") {
            logger.info("Handling system message");
            const chatSyncCommand = new ChatSyncCommand({
                applicationId: secretData.AMAZON_Q_APP_ID,
                userMessage: JSON.stringify(lastMessage),
                chatMode: "CREATOR_MODE"
            });
            const chatSyncResponse = await qBusinessClient.send(chatSyncCommand);
            logger.info("Received chatSyncResponse");
            return res.json({
                id: "chatcmpl-system",
                object: "chat.completion",
                created: Math.floor(Date.now() / 1000),
                model: "askcto",
                choices: [{
                    message: { role: "system", content: chatSyncResponse.systemMessage || "No response received" },
                    index: 0,
                    finish_reason: "stop"
                }]
            });
        }

        logger.info("Handling normal chat message");
        const conversationMessagesString = JSON.stringify(conversationMessages);

        // Create an async generator function for inputStream events
        async function* createInputStream() {
            // First, yield the configuration event
            yield { configurationEvent: { chatMode: "CREATOR_MODE" } };
        
            // Next, yield the text event with your conversation messages
            yield { textEvent: { userMessage: conversationMessagesString } };
        
            // Finally, yield the end-of-input event to signal the end
            yield { endOfInputEvent: {} };
        }

        // Wrap your event payload in an async iterable:
        const input = {
            applicationId: secretData.AMAZON_Q_APP_ID,
            inputStream: createInputStream()
        }
        const chatCommand = new ChatCommand(input);

        logger.info("Sending chat command");
        const response = await qBusinessClient.send(chatCommand);
        logger.info("Received response from QBusiness API");

        // Set up SSE headers.
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache");
        res.setHeader("Connection", "keep-alive");
        // Optionally send an initial comment.
        res.write(": connected\n\n");
        let firstChunk = true;
        for await (const event of response.outputStream) {
            if (event.textEvent) {
                const delta = { content: event.textEvent.systemMessage };
                if (firstChunk) {
                    delta.role = "assistant";
                    firstChunk = false;
                }
                const data = {
                    id: "chatcmpl-" + event.textEvent.systemMessageId,
                    object: "chat.completion.chunk",
                    created: Math.floor(Date.now() / 1000),
                    model: "askcto",
                    choices: [
                        { delta, index: 0, finish_reason: null }
                    ]
                };
                res.write(`data: ${JSON.stringify(data)}\n\n`);
            }
        }
        // Send a final JSON chunk with finish_reason "stop"
        const finalChunk = {
            id: "chatcmpl-final",
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: "askcto",
            choices: [{
            delta: {},
            index: 0,
            finish_reason: "stop"
            }]
        };
        res.write(`data: ${JSON.stringify(finalChunk)}\n\n`);
        res.end();
    } catch (error) {
        logger.error(`Error processing request: ${error}`);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
