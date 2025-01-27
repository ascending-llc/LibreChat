# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import StreamingResponse
# from pydantic import BaseModel
# import boto3
# import json
# import os
# import logging

# # Set up logging
# logging.basicConfig(
#     level=logging.DEBUG,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     handlers=[
#         logging.StreamHandler(),  # Log to the console
#         logging.FileHandler("/app/openai_api.log")  # Log to a file in the container
#     ]
# )

# logger = logging.getLogger(__name__)

# # AWS configuration
# AWS_REGION = os.getenv("AWS_REGION", "us-east-1")  # Default AWS region
# APPLICATION_ID = os.getenv("APPLICATION_ID", "9f3542b8-2f5f-44ec-9ef8-df643041b5ea")  # Application ID for Q Business
# Q_BUSINESS_CLIENT = boto3.client("qbusiness", region_name=AWS_REGION)

# # Initialize FastAPI app
# app = FastAPI()

# # Define the request model
# class ChatCompletionRequest(BaseModel):
#     messages: list

# @app.post("/v1/chat/completions")
# async def chat_completions(request: ChatCompletionRequest):
#     """
#     Handles POST requests to /v1/chat/completions. Integrates with Amazon Q Business's chat_sync API.
#     Converts the synchronous response into a streaming format.
#     """
#     logger.debug(f"Received request: {request}")
    
#     messages = request.messages

#     # Prepare Q Business input
#     input_text = "\n".join(
#         msg["content"] for msg in messages if msg["role"] == "user"
#     )

#     logger.debug(f"Generated input text: {input_text}")

#     try:
#         # Call the Q Business chat_sync API
#         response = Q_BUSINESS_CLIENT.chat_sync(
#             applicationId=APPLICATION_ID,
#             userMessage=input_text,  # Pass the user's input
#         )
#         logger.debug(f"Q Business API response: {response}")

#         # Extract the response text
#         response_text = response.get("systemMessage", "No response from Q Business.")
#         tokens = response_text.split()  # Split response into tokens for streaming
#         logger.debug(f"Tokenized response: {tokens}")

#     except Exception as e:
#         logger.error(f"Error calling Q Business API: {e}")
#         tokens = ["Error", "connecting", "to", "Q", "Business."]

#     # Stream tokens in OpenAI-style SSE
#     async def stream_generator():
#         for index, token in enumerate(tokens):
#             chunk_json = {
#                 "id": "chatcmpl-qbusiness",
#                 "object": "chat.completion.chunk",
#                 "created": 1234567890,
#                 "model": "q-business-model",
#                 "choices": [{
#                     "delta": {
#                         "role": "assistant",  # Add the role field here
#                         "content": token
#                     },
#                     "index": 0,
#                     "finish_reason": None if index < len(tokens) - 1 else "stop"
#                 }]
#             }
#             yield f"data: {json.dumps(chunk_json)}\n\n"
#         # Indicate the end of the stream
#         yield "data: [DONE]\n\n"

#     return StreamingResponse(stream_generator(), media_type="text/event-stream")

# if __name__ == "__main__":
#     import uvicorn
#     # Run FastAPI app
#     uvicorn.run(app, host="0.0.0.0", port=8080)


# from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import StreamingResponse
# from pydantic import BaseModel
# import boto3
# import json
# import os
# import logging
# import requests

# # Set up logging
# logging.basicConfig(
#     level=logging.DEBUG,
#     format="%(asctime)s [%(levelname)s] %(message)s",
#     handlers=[
#         logging.StreamHandler(),
#         logging.FileHandler("/app/openai_api.log")
#     ]
# )

# logger = logging.getLogger(__name__)

# # Azure Entra ID configuration
# AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
# AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
# AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID")
# AZURE_OIDC_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"

# # AWS configuration
# AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
# APPLICATION_ID = os.getenv("APPLICATION_ID", "9f3542b8-2f5f-44ec-9ef8-df643041b5ea")
# IAM_ROLE = os.getenv("IAM_ROLE")
# IDC_APPLICATION_ID = os.getenv("IDC_APPLICATION_ID")

# # Initialize FastAPI app
# app = FastAPI()

# # Define the request model
# class ChatCompletionRequest(BaseModel):
#     messages: list


# def get_oidc_token_from_azure():
#     """
#     Retrieve an OIDC token from Azure Entra ID.
#     """
#     payload = {
#         "client_id": AZURE_CLIENT_ID,
#         "client_secret": AZURE_CLIENT_SECRET,
#         "grant_type": "client_credentials",
#         "scope": "https://graph.microsoft.com/.default",
#     }
#     response = requests.post(AZURE_OIDC_URL, data=payload)

#     if response.status_code == 200:
#         oidc_token = response.json().get("access_token")
#         logger.info("Successfully retrieved OIDC token from Azure.")
#         return oidc_token
#     else:
#         logger.error(f"Failed to retrieve OIDC token: {response.text}")
#         raise Exception("Unable to fetch OIDC token from Azure.")


# def exchange_azure_token_with_idc_token(oidc_token):
#     """
#     Exchange Azure OIDC token for AWS Identity Center token.
#     """
#     client = boto3.client("sso-oidc", region_name=AWS_REGION)
#     response = client.create_token(
#         clientId=IDC_APPLICATION_ID,
#         grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
#         assertion=oidc_token,  # Use the Azure OIDC token
#     )
#     return response.get("access_token")


# def assume_role_with_idc_token(idc_token):
#     """
#     Assume an AWS IAM role using the AWS Identity Center token.
#     """
#     sts_client = boto3.client("sts", region_name=AWS_REGION)
#     response = sts_client.assume_role_with_web_identity(
#         RoleArn=IAM_ROLE,
#         RoleSessionName="chat-sync-session",
#         WebIdentityToken=idc_token,
#     )
#     return response["Credentials"]


# @app.post("/v1/chat/completions")
# async def chat_completions(request: ChatCompletionRequest):
#     """
#     Handles POST requests to /v1/chat/completions. Integrates with Amazon Q Business's chat_sync API.
#     Converts the synchronous response into a streaming format.
#     """
#     logger.debug(f"Received request: {request}")
#     messages = request.messages

#     # Prepare Q Business input
#     input_text = "\n".join(
#         msg["content"] for msg in messages if msg["role"] == "user"
#     )
#     logger.debug(f"Generated input text: {input_text}")

#     try:
#         # Step 1: Retrieve OIDC token from Azure
#         azure_oidc_token = get_oidc_token_from_azure()

#         # Step 2: Exchange Azure OIDC token for AWS Identity Center token
#         idc_token = exchange_azure_token_with_idc_token(azure_oidc_token)

#         # Step 3: Assume IAM role using Identity Center token
#         credentials = assume_role_with_idc_token(idc_token)

#         # Step 4: Configure AWS client with temporary credentials
#         qbusiness_client = boto3.client(
#             "qbusiness",
#             region_name=AWS_REGION,
#             aws_access_key_id=credentials["AccessKeyId"],
#             aws_secret_access_key=credentials["SecretAccessKey"],
#             aws_session_token=credentials["SessionToken"],
#         )

#         # Call the Q Business chat_sync API
#         response = qbusiness_client.chat_sync(
#             applicationId=APPLICATION_ID,
#             userMessage=input_text,
#         )
#         logger.debug(f"Q Business API response: {response}")

#         # Extract the response text
#         response_text = response.get("systemMessage", "No response from Q Business.")
#         tokens = response_text.split()  # Split response into tokens for streaming
#         logger.debug(f"Tokenized response: {tokens}")

#     except Exception as e:
#         logger.error(f"Error calling Q Business API: {e}")
#         tokens = ["Error", "connecting", "to", "Q", "Business."]

#     # Stream tokens in OpenAI-style SSE
#     async def stream_generator():
#         for index, token in enumerate(tokens):
#             chunk_json = {
#                 "id": "chatcmpl-qbusiness",
#                 "object": "chat.completion.chunk",
#                 "created": 1234567890,
#                 "model": "q-business-model",
#                 "choices": [{
#                     "delta": {
#                         "role": "assistant",
#                         "content": token
#                     },
#                     "index": 0,
#                     "finish_reason": None if index < len(tokens) - 1 else "stop"
#                 }]
#             }
#             yield f"data: {json.dumps(chunk_json)}\n\n"
#         yield "data: [DONE]\n\n"

#     return StreamingResponse(stream_generator(), media_type="text/event-stream")


# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8080)


# from fastapi import FastAPI, Request
# from fastapi.responses import StreamingResponse
# from pydantic import BaseModel
# import boto3
# import json
# import os
# import logging
# from typing import List, Dict, Any

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
# )
# logger = logging.getLogger(__name__)

# # Configuration
# class Config:
#     AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
#     APPLICATION_ID = os.getenv("APPLICATION_ID")
#     ROLE_ARN = os.getenv("ROLE_ARN")
    
#     # For IAM user authentication
#     AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
#     AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
#     AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN")

# app = FastAPI()

# class ChatMessage(BaseModel):
#     role: str
#     content: str

# class ChatCompletionRequest(BaseModel):
#     messages: List[ChatMessage]
#     stream: bool = True

# class QBusinessClient:
#     def __init__(self):
#         self.session = boto3.Session(
#             aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
#             aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
#             aws_session_token=Config.AWS_SESSION_TOKEN,
#             region_name=Config.AWS_REGION
#         )
        
#         # If using role assumption
#         if Config.ROLE_ARN:
#             sts_client = self.session.client('sts')
#             assumed_role = sts_client.assume_role(
#                 RoleArn=Config.ROLE_ARN,
#                 RoleSessionName='QBusinessSession'
#             )
            
#             # Create new session with temporary credentials
#             self.session = boto3.Session(
#                 aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
#                 aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
#                 aws_session_token=assumed_role['Credentials']['SessionToken'],
#                 region_name=Config.AWS_REGION
#             )
        
#         self.client = self.session.client('qbusiness')

#     async def chat_sync(self, message: str) -> Dict[str, Any]:
#         try:
#             response = self.client.chat_sync(
#                 applicationId=Config.APPLICATION_ID,
#                 userMessage=message
#             )
#             return response
#         except Exception as e:
#             logger.error(f"Error in chat_sync: {str(e)}")
#             raise

# @app.post("/v1/chat/completions")
# async def chat_completions(request: ChatCompletionRequest):
#     try:
#         # Initialize Q Business client
#         q_client = QBusinessClient()
        
#         # Extract the last user message
#         user_messages = [msg.content for msg in request.messages if msg.role == "user"]
#         if not user_messages:
#             raise ValueError("No user messages found in the request")
        
#         last_message = user_messages[-1]
        
#         # Call Q Business API
#         response = await q_client.chat_sync(last_message)
        
#         # Extract response text
#         response_text = response.get("systemMessage", "No response received")
#         tokens = response_text.split()  # Simple tokenization

#         async def stream_generator():
#             for i, token in enumerate(tokens):
#                 chunk = {
#                     "id": f"chatcmpl-{i}",
#                     "object": "chat.completion.chunk",
#                     "created": 1234567890,
#                     "model": "amazon-q-business",
#                     "choices": [{
#                         "delta": {
#                             "role": "assistant",
#                             "content": token + " "
#                         },
#                         "index": 0,
#                         "finish_reason": "stop" if i == len(tokens) - 1 else None
#                     }]
#                 }
#                 yield f"data: {json.dumps(chunk)}\n\n"
#             yield "data: [DONE]\n\n"

#         return StreamingResponse(
#             stream_generator(),
#             media_type="text/event-stream"
#         )

#     except Exception as e:
#         logger.error(f"Error processing request: {str(e)}")
#         raise

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8080)


from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import boto3
import json
import os
import logging
import requests

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/app/openai_api.log")
    ]
)

logger = logging.getLogger(__name__)

# Azure Entra ID configuration
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID")
AZURE_OIDC_URL = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"

# AWS configuration
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
APPLICATION_ID = os.getenv("APPLICATION_ID", "9f3542b8-2f5f-44ec-9ef8-df643041b5ea")

# This IAM role must trust your Azure AD OIDC provider and allow sts:AssumeRoleWithWebIdentity
IAM_ROLE = os.getenv("IAM_ROLE")

# Initialize FastAPI app
app = FastAPI()

# Define the request model
class ChatCompletionRequest(BaseModel):
    messages: list

def get_oidc_token_from_azure():
    """
    Retrieve an OIDC token from Azure Entra ID using client_credentials grant.
    Make sure your Azure AD app registration is configured for the correct scope.
    """
    payload = {
        "client_id": AZURE_CLIENT_ID,
        "client_secret": AZURE_CLIENT_SECRET,
        "grant_type": "client_credentials",
        # Replace this scope with what your Azure app registration requires
        "scope": "https://graph.microsoft.com/.default",
    }
    response = requests.post(AZURE_OIDC_URL, data=payload)

    if response.status_code == 200:
        oidc_token = response.json().get("access_token")
        logger.info("Successfully retrieved OIDC token from Azure.")
        return oidc_token
    else:
        logger.error(f"Failed to retrieve OIDC token: {response.text}")
        raise Exception("Unable to fetch OIDC token from Azure.")

@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest):
    """
    Handles POST requests to /v1/chat/completions. Integrates with Amazon Q Business's chat_sync API.
    Converts the synchronous response into a streaming format.
    """
    logger.debug(f"Received request: {request}")
    messages = request.messages

    # Prepare Q Business input
    input_text = "\n".join(
        msg["content"] for msg in messages if msg["role"] == "user"
    )
    logger.debug(f"Generated input text: {input_text}")

    try:
        # 1. Retrieve OIDC token from Azure
        azure_oidc_token = get_oidc_token_from_azure()

        # 2. Call STS to assume role with web identity (the Azure OIDC token)
        sts_client = boto3.client("sts", region_name=AWS_REGION)
        assume_response = sts_client.assume_role_with_web_identity(
            RoleArn=IAM_ROLE,
            RoleSessionName="chat-sync-session",
            WebIdentityToken=azure_oidc_token
        )
        credentials = assume_response["Credentials"]

        # 3. Configure QBusiness client with these temporary credentials
        qbusiness_client = boto3.client(
            "qbusiness",
            region_name=AWS_REGION,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

        # 4. Call the Q Business chat_sync API
        response = qbusiness_client.chat_sync(
            applicationId=APPLICATION_ID,
            userMessage=input_text,
        )
        logger.debug(f"Q Business API response: {response}")

        # 5. Extract the response text
        response_text = response.get("systemMessage", "No response from Q Business.")
        tokens = response_text.split()  # Split response into tokens for streaming
        logger.debug(f"Tokenized response: {tokens}")

    except Exception as e:
        logger.error(f"Error calling Q Business API: {e}")
        tokens = ["Error", "connecting", "to", "Q", "Business."]

    # Stream tokens in OpenAI-style SSE
    async def stream_generator():
        for index, token in enumerate(tokens):
            chunk_json = {
                "id": "chatcmpl-qbusiness",
                "object": "chat.completion.chunk",
                "created": 1234567890,
                "model": "q-business-model",
                "choices": [{
                    "delta": {
                        "role": "assistant",
                        "content": token
                    },
                    "index": 0,
                    "finish_reason": None if index < len(tokens) - 1 else "stop"
                }]
            }
            yield f"data: {json.dumps(chunk_json)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(stream_generator(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
