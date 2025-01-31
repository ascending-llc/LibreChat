from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import requests
import boto3
import jwt
import json
import os
import logging
import datetime
from typing import List, Dict, Any

# Set AWS region globally
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class SecretManager:
    """Handles retrieval and updating of secrets in AWS Secrets Manager."""

    SECRET_NAME = "q_business_api_config"

    @staticmethod
    def get_secret() -> Dict[str, str]:
        """Retrieve a secret from AWS Secrets Manager."""
        client = boto3.client("secretsmanager", region_name=AWS_REGION)
        try:
            response = client.get_secret_value(SecretId=SecretManager.SECRET_NAME)
            secret_data = json.loads(response["SecretString"])
            return secret_data
        except Exception as e:
            logger.error(f"Error retrieving secret {SecretManager.SECRET_NAME}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to retrieve secret: {SecretManager.SECRET_NAME}")

    @staticmethod
    def update_secret(updated_fields: Dict[str, str]):
        """Update specific fields in the existing secret in AWS Secrets Manager."""
        client = boto3.client("secretsmanager", region_name=AWS_REGION)

        try:
            # Retrieve the current secret from Secrets Manager
            current_secret = SecretManager.get_secret()

            # Update only the specified fields
            current_secret.update(updated_fields)

            # Write back the updated secret to AWS Secrets Manager
            client.put_secret_value(
                SecretId=SecretManager.SECRET_NAME,
                SecretString=json.dumps(current_secret)  # Save only the modified fields
            )

            logger.info(f"Successfully updated fields in secret: {SecretManager.SECRET_NAME}")
        except Exception as e:
            logger.error(f"Error updating secret {SecretManager.SECRET_NAME}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to update secret: {SecretManager.SECRET_NAME}")


class Config:
    """Loads application configuration from Secrets Manager."""
    
    @classmethod
    def load(cls):
        """Retrieve configuration from Secrets Manager."""
        secret_data = SecretManager.get_secret()

        cls.COGNITO_DOMAIN = secret_data.get("COGNITO_DOMAIN")
        cls.CLIENT_ID = secret_data.get("CLIENT_ID")
        cls.CLIENT_SECRET = secret_data.get("CLIENT_SECRET")
        cls.REDIRECT_URI = secret_data.get("REDIRECT_URI")
        cls.IAM_ROLE = secret_data.get("IAM_ROLE")
        cls.IDC_APPLICATION_ID = secret_data.get("IDC_APPLICATION_ID")
        cls.AMAZON_Q_APP_ID = secret_data.get("AMAZON_Q_APP_ID")
        cls.TOKEN_ENDPOINT = f"{cls.COGNITO_DOMAIN}/oauth2/token"

# Load configuration once at startup
Config.load()

class CognitoAuth:
    """Handles authentication using Cognito and IAM Identity Center tokens."""

    @staticmethod
    def get_valid_idc_id_token() -> str:
        """
        Retrieves a valid IDC ID token.
        If expired, refreshes it using Cognito ID token.
        If missing, refresh Cognito ID token first, then exchange for IDC token.
        """
        secret_data = SecretManager.get_secret()
        idc_id_token = secret_data.get("IDC_TOKEN")
        cognito_refresh_token = secret_data.get("COGNITO_REFRESH_TOKEN")

        if idc_id_token and not CognitoAuth._is_token_expired(idc_id_token):
            logger.info("Using valid IDC ID token from Secrets Manager.")
            return idc_id_token

        if cognito_refresh_token:
            if idc_id_token:
                logger.info("IDC ID token expired. Attempting refresh using Cognito refresh token.")
                new_idc_id_token = CognitoAuth._refresh_idc_id_token(cognito_refresh_token)
            else:
                logger.info("No valid IDC ID token found. Refreshing Cognito ID token first.")
                new_cognito_id_token = CognitoAuth._refresh_cognito_id_token(cognito_refresh_token)
                new_idc_id_token = CognitoAuth._exchange_token_with_identity_center(new_cognito_id_token)

            CognitoAuth._store_idc_tokens(new_idc_id_token, cognito_refresh_token)
            return new_idc_id_token

        raise HTTPException(status_code=500, detail="No valid IDC ID token and no Cognito refresh token available.")

    @staticmethod
    def _is_token_expired(token: str) -> bool:
        """Check if the token is expired."""
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = decoded.get("exp")
            if exp_timestamp is None:
                logger.warning("Token does not have an 'exp' claim.")
                return True
            # Convert expiration timestamp to UTC datetime
            exp_dt = datetime.datetime.fromtimestamp(exp_timestamp, datetime.timezone.utc)

            # Get current UTC time
            now = datetime.datetime.now(datetime.timezone.utc)

            # Check if the token is expired, allowing a 30-second leeway for clock skew
            return now >= exp_dt - datetime.timedelta(seconds=30)
        except Exception as e:
            logger.error(f"Error decoding token: {e}")
            return True

    @staticmethod
    def _refresh_cognito_id_token(refresh_token: str) -> str:
        """Refresh Cognito ID token."""
        try:
            response = requests.post(
                Config.TOKEN_ENDPOINT,
                data={
                    "grant_type": "refresh_token",
                    "client_id": Config.CLIENT_ID,
                    "client_secret": Config.CLIENT_SECRET,
                    "refresh_token": refresh_token,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            return response.json()["id_token"]
        except requests.RequestException as e:
            logger.error(f"Error refreshing Cognito ID token: {e}")
            raise HTTPException(status_code=500, detail="Failed to refresh Cognito ID token.")

    @staticmethod
    def _refresh_idc_id_token(refresh_token: str) -> str:
        """Refresh IDC ID token."""
        try:
            client = boto3.client("sso-oidc", region_name=AWS_REGION)
            response = client.create_token_with_iam(
                clientId=Config.IDC_APPLICATION_ID,
                grantType="refresh_token",
                refreshToken=refresh_token,
            )
            return response.get("idToken")
        except Exception as e:
            logger.warning(f"Failed to refresh IDC ID token: {e}")
            return None

    @staticmethod
    def _exchange_token_with_identity_center(id_token: str) -> tuple:
        """Exchange Cognito ID token for IDC ID token."""
        try:
            client = boto3.client("sso-oidc", region_name=AWS_REGION)
            response = client.create_token_with_iam(
                clientId=Config.IDC_APPLICATION_ID,
                grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion=id_token,
            )
            return response["idToken"]
        except Exception as e:
            logger.error(f"Error exchanging token with Identity Center: {e}")
            raise HTTPException(status_code=500, detail="Failed to exchange Cognito ID token with Identity Center.")
        
    @staticmethod
    def assume_role_with_token(iam_token: str):
        """Assume the IAM role using the IAM OIDC token."""
        decoded_token = jwt.decode(iam_token, options={"verify_signature": False})
        sts_client = boto3.client("sts", region_name=AWS_REGION)
        try:
            response = sts_client.assume_role(
                RoleArn=Config.IAM_ROLE,
                RoleSessionName="qapp",
                ProvidedContexts=[
                    {
                        "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                        "ContextAssertion": decoded_token["sts:identity_context"],
                    }
                ],
            )
            return response["Credentials"]
        except Exception as e:
            logger.error(f"Error assuming role with token: {e}")
            raise

    @staticmethod
    def _store_idc_tokens(idc_id_token: str, cognito_refresh_token: str):
        """Store only IDC ID token and Cognito refresh token in Secrets Manager without overwriting other values."""
        SecretManager.update_secret({
            "IDC_TOKEN": idc_id_token,
            "COGNITO_REFRESH_TOKEN": cognito_refresh_token
        })

app = FastAPI()

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    messages: List[ChatMessage]
    stream: bool = True

class QBusinessClient:
    def __init__(self, aws_credentials: Dict[str, str]):
        self.session = boto3.Session(
            aws_access_key_id=aws_credentials["AccessKeyId"],
            aws_secret_access_key=aws_credentials["SecretAccessKey"],
            aws_session_token=aws_credentials["SessionToken"],
        )
        self.client = self.session.client("qbusiness", region_name=AWS_REGION)

    async def chat_sync(self, message: str, conversation_id="", parent_message_id="") -> Dict[str, Any]:
        """Call Q Business API to get a response."""
        try:
            if conversation_id:
                response = self.client.chat_sync(
                    applicationId=Config.AMAZON_Q_APP_ID,
                    userMessage=message,
                    conversationId=conversation_id,
                    parentMessageId=parent_message_id,
                    chatMode='CREATOR_MODE'
                )
            else:
                response = self.client.chat_sync(
                    applicationId=Config.AMAZON_Q_APP_ID,
                    userMessage=message,
                    chatMode='CREATOR_MODE'
                )
            return response
        except Exception as e:
            logger.error(f"Error in chat_sync: {e}")
            raise

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest):
    try:
        # Retrieve a valid access token from Secrets Manager
        idc_id_token = CognitoAuth.get_valid_idc_id_token()
        if not idc_id_token:
            raise HTTPException(status_code=500, detail="Failed to retrieve a valid idc id token.")
        
        # Assume IAM role using the IAM token
        aws_credentials = CognitoAuth.assume_role_with_token(idc_id_token)

        # Initialize Q Business client
        q_client = QBusinessClient(aws_credentials)

        # Extract the last user message
        user_messages = [msg.content for msg in request.messages if msg.role == "user"]
        if not user_messages:
            raise HTTPException(status_code=400, detail="No user messages found in the request.")

        last_message = user_messages[-1]

        # Call Q Business API
        response = await q_client.chat_sync(last_message)

        # Extract response text
        response_text = response.get("systemMessage", "No response received")
        tokens = response_text.split()  # Simple tokenization

        async def stream_generator():
            for i, token in enumerate(tokens):
                chunk = {
                    "id": f"chatcmpl-{i}",
                    "object": "chat.completion.chunk",
                    "created": 1234567890,
                    "model": "amazon-q-business",
                    "choices": [{
                        "delta": {
                            "role": "assistant",
                            "content": token + " "
                        },
                        "index": 0,
                        "finish_reason": "stop" if i == len(tokens) - 1 else None
                    }]
                }
                yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream"
        )

    except Exception as e:
        logger.error(f"Error processing request: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
