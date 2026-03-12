#!/bin/bash
# Registration
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "phone": "1234567890",
    "password": "Password123!",
    "securityAnswers": [
      {"questionId": 1, "answer": "Answer1"},
      {"questionId": 2, "answer": "Answer2"},
      {"questionId": 3, "answer": "Answer3"}
    ]
  }'

# Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Password123!"
  }'

# Vault Operations (Replace <TOKEN> with actual token)
# List entries
# curl http://localhost:8080/api/vault -H "Authorization: Bearer <TOKEN>"

# Password Generation
# curl -X POST http://localhost:8080/api/password/generate \
#   -H "Content-Type: application/json" \
#   -H "Authorization: Bearer <TOKEN>" \
#   -d '{"length": 16, "useUppercase": true, "useNumbers": true, "useSpecial": true}'
