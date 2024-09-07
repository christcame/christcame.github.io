import os
from flask import Flask, jsonify, request
from mistralai import Mistral, UserMessage

app = Flask(__name__)

# Initialize Mistral AI client
client = Mistral(
    api_key=os.getenv("GITHUB_TOKEN"),
    endpoint="https://models.inference.ai.azure.com"
)

def get_mistral_response(prompt):
    """Get a response from the Mistral AI model."""
    response = client.chat.complete(
        model="Mistral-large-2407",
        messages=[
            ChatMessage(role="system", content="You are an AI assistant that provides information about GitHub and its features."),
            ChatMessage(role="user", content=prompt)
        ],
        temperature=0.7,
        max_tokens=4096,
        top_p=1.0
    )
    return response.choices[0].message.content

@app.route('/user/<username>', methods=['GET'])
def get_user_info(username):
    """Get information about a GitHub user."""
    prompt = f"Provide information about the GitHub user {username}."
    return jsonify({"response": get_mistral_response(prompt)})

@app.route('/repos/<username>', methods=['GET'])
def get_user_repos(username):
    """Get information about repositories of a GitHub user."""
    prompt = f"List and describe some notable repositories of the GitHub user {username}."
    return jsonify({"response": get_mistral_response(prompt)})

@app.route('/create_repo', methods=['POST'])
def create_repo():
    """Provide information about creating a new repository on GitHub."""
    data = request.json
    repo_name = data.get('name', 'example-repo')
    prompt = f"Explain the process of creating a new GitHub repository named {repo_name}."
    return jsonify({"response": get_mistral_response(prompt)})

@app.route('/issues/<owner>/<repo>', methods=['GET'])
def get_repo_issues(owner, repo):
    """Get information about issues in a specific repository."""
    prompt = f"Describe common types of issues that might be found in the GitHub repository {owner}/{repo}."
    return jsonify({"response": get_mistral_response(prompt)})

if __name__ == '__main__':
    app.run(debug=True)
