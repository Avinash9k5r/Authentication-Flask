# Authentication-Flask
A Flask application for authentication

## How to Run the application

Install Libraries `pip install -r requirements.txt`

Run application `python app.py`

## Curl Commands to test various scenario

1. Sign up -> `curl -X POST http://127.0.0.1:5000/signup -H "Content-Type: application/json" -d "{\"email\": \"test@example.com\", \"password\": \"securepassword\"}"`

2. Sign in -> `curl -X POST http://127.0.0.1:5000/signin -H "Content-Type: application/json" -d "{\"email\": \"test@example.com\", \"password\": \"securepassword\"}"`

3. A protected route that requires a valid token to access -> `curl -X GET http://127.0.0.1:5000/protected -H "Authorization: Bearer <access_token>"`

3. Revoke Token -> `curl -X POST http://127.0.0.1:5000/revoke -H "Authorization: Bearer <access_token>"`

5. Refresh Token -> `curl -X POST http://127.0.0.1:5000/refresh -H "Content-Type: application/json" -d "{\"refresh_token\": \"<refresh_token>\"}"`
