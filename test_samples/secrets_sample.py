# Hardcoded secrets sample
import requests

# Hardcoded API keys
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456"
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefgh"
password = "SuperSecret123!"

# AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database connection with embedded password
DATABASE_URL = "postgres://admin:password123@localhost:5432/mydb"

# GitHub token
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

def call_api():
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)
