from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Secret keys
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['REFRESH_SECRET_KEY'] = 'your_refresh_secret_key_here'

# In-memory storage
users = {}
revoked_tokens = set()  
refresh_tokens = {} 

# Decorator to check token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Extract token from the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
            
        # Check if token is missing
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        # Check if token is revoked
        if token in revoked_tokens:
            return jsonify({'message': 'Token has been revoked!'}), 401

        try:
            # Decode and verify token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = data  # Attach user data to request
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401

        return f(*args, **kwargs)
    return decorated

# Sign Up Route
@app.route('/signup', methods=['POST'])
def signup():
    # Get email and password from request
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Validate input
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    if email in users:
        return jsonify({'message': 'User already exists!'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password)

    # Store user in memory
    users[email] = {'password': hashed_password}
    return jsonify({'message': 'User created successfully!'}), 201

# Sign In Route
@app.route('/signin', methods=['POST'])
def signin():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Validate input
    if not email or not password:
        return jsonify({'message': 'Email and password are required!'}), 400

    # Check if user exists and verify password
    user = users.get(email)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Create JWT payload (expires in 30 minutes)
    access_payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'iat': datetime.datetime.utcnow()  # Issued at
    }

    # Generate JWT token
    access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')

    # Create refresh token (expires in 7 days)
    refresh_payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    refresh_token = jwt.encode(refresh_payload, app.config['REFRESH_SECRET_KEY'], algorithm='HS256')

    # Store the refresh token
    refresh_tokens[email] = refresh_token

    # Return token in response
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


# A protected route that requires a valid token to access
@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({'message': 'This is a protected route.', 'user': request.user})

# Revoke token route
@app.route('/revoke', methods=['POST'])
@token_required
def revoke_token():
    # Extract the token from the request headers
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(" ")[1] if auth_header and auth_header.startswith("Bearer ") else None

    if not token:
        return jsonify({'message': 'Token is required for revocation!'}), 400

    # Add token to the blacklist
    revoked_tokens.add(token)
    return jsonify({'message': 'Token has been revoked!'}), 200

# Refresh token route (to get a new access token)
@app.route('/refresh', methods=['POST'])
def refresh_token():
    data = request.json
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is required!'}), 400

    try:
        # Decode the refresh token
        refresh_data = jwt.decode(refresh_token, app.config['REFRESH_SECRET_KEY'], algorithms=['HS256'])

        # Check if the refresh token exists in our storage
        email = refresh_data['email']
        if refresh_tokens.get(email) != refresh_token:
            return jsonify({'message': 'Invalid refresh token!'}), 401

        # Create a new access token
        access_payload = {
            'email': email,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),  # 30 minutes expiration
            'iat': datetime.datetime.utcnow()
        }
        new_access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'access_token': new_access_token}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Refresh token has expired!'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token!'}), 401


if __name__ == '__main__':
    app.run(debug=True)
