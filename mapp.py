"""Run this model in Python

> pip install mistralai
"""
import os
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage

# To authenticate with the model you will need to generate a personal access token (PAT) in your GitHub settings. 
# Create your PAT token by following instructions here: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
client = MistralClient(
    api_key=os.environ["GITHUB_TOKEN"],
    endpoint="https://models.inference.ai.azure.com"
)

response = client.chat(
    model="Mistral-large-2407",
    messages=[
        ChatMessage(role="system", content=""),
        ChatMessage(role="user", content="What is the capital of France?"),
    ],
    temperature=0.7,
    max_tokens=4096,
    top_p=1    
)

print(response.choices[0].message.content)
