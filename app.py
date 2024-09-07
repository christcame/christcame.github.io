import os
from mistralai import Mistral, UserMessage, SystemMessage

token = os.environ["GITHUB_TOKEN"]
endpoint = "https://models.inference.ai.azure.com"
model_name = "Mistral-large-2407"

client = Mistral(api_key=token, server_url=endpoint)

response = client.chat.complete(
    model=model_name,
    messages=[
        SystemMessage(content="You are a helpful assistant."),
        UserMessage(content="What is the capital of France?"),
    ],
    temperature=1.,
    max_tokens=1000,
    top_p=1.
)

print(response.choices[0].message.content)
