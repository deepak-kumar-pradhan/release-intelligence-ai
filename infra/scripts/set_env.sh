#!/usr/bin/env bash
set -euo pipefail

# Set environment variables for Azure AI Foundry deployment
export AZURE_ENV_NAME="chat-playground-5296"
export AZURE_LOCATION="eastus2"
export AZURE_SUBSCRIPTION_ID="380610ea-ded5-4a19-a621-381bacb3ba8a"
export AZURE_EXISTING_AIPROJECT_ENDPOINT="https://ri-hackathon-resource.openai.azure.com/openai/v1"
export AZURE_EXISTING_AIPROJECT_RESOURCE_ID="/subscriptions/380610ea-ded5-4a19-a621-381bacb3ba8a/resourceGroups/rg-ri-hackathon/providers/Microsoft.CognitiveServices/accounts/ri-hackathon-resource/projects/ri-hackathon"
export AZD_ALLOW_NON_EMPTY_FOLDER=true

# Additional vars for deployment
export AI_PROJECT_NAME="ri-hackathon"
export ACR_LOGIN_SERVER="your-acr-login-server.azurecr.io"  # Replace with your ACR
export AZURE_OPENAI_ENDPOINT="$AZURE_EXISTING_AIPROJECT_ENDPOINT"
export AZURE_OPENAI_API_KEY="your-openai-api-key"  # Replace with your key
export AZURE_OPENAI_DEPLOYMENT="gpt-4o-mini"
export AZURE_OPENAI_API_VERSION="2024-07-18"

echo "Environment variables set. Now run:"
