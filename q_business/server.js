import express from 'express';
import { STSClient, AssumeRoleCommand } from "@aws-sdk/client-sts";
import { QBusinessClient, ChatCommand, ChatSyncCommand } from "@aws-sdk/client-qbusiness";
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import winston from 'winston';
import { TokenManager } from './TokenManager.js';

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
const stsClient = new STSClient({ region: AWS_REGION });

app.use(express.json());

async function assumeRoleWithToken(iamToken) {
    const tokenManager = new TokenManager();
    // const secretData = await getSecret();
    const secretData = await tokenManager.getSecret();
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
        const tokenManager = new TokenManager();
        const idcIdToken = await tokenManager.getValidIDCIdToken();
        logger.info("Retrieved IDC ID Token");
        // const idcIdToken = await getValidIDCIdToken();
        // logger.info("Retrieved IDC ID Token");
        const awsCredentials = await assumeRoleWithToken(idcIdToken);
        logger.info("Assumed role with token");

        // Retrieve secret data for additional parameters
        const secretData = await tokenManager.getSecret();
        logger.info("Retrieved secret data");
        
        // const secretData = await getSecret();
        // logger.info("Retrieved secret data");

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
