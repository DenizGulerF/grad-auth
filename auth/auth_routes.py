from flask import Blueprint, request, jsonify, current_app
import bcrypt
import jwt
from datetime import datetime, timedelta
import uuid
from couchbase.options import QueryOptions


auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        if not data or not data.get('username') or not data.get('password'):
            return jsonify({"error": "Username and password are required"}), 400

        username = data.get('username')
        password = data.get('password')

        # Couchbase bağlantılarını al
        collection = current_app.config.get('COUCHBASE_COLLECTION')
        username_collection = current_app.config.get('COUCHBASE_USERNAME_COLLECTION')

        if not collection or not username_collection:
            return jsonify({"error": "Database connection not available"}), 500

        try:
            # username -> user_id eşleşmesini al
            result = username_collection.get(f"username::{username}")
            user_id = result.content_as[dict]['user_id']

            # user_id -> kullanıcı bilgilerini al
            result = collection.get(f"user::{user_id}")
            user = result.content_as[dict]

            # Şifreyi doğrula
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                payload = {
                    'sub': user_id,
                    'username': username,
                    'roles': user.get('roles', ['user']),
                    'iat': datetime.utcnow(),
                    'exp': datetime.utcnow() + timedelta(hours=24)
                }

                token = jwt.encode(
                    payload,
                    current_app.config['JWT_SECRET_KEY'],
                    algorithm='HS256'
                )

                user_data = {k: v for k, v in user.items() if k != 'password'}

                return jsonify({
                    "message": "Login successful",
                    "user": user_data,
                    "token": token
                }), 200

            return jsonify({"error": "Invalid credentials"}), 401

        except Exception as e:
            return jsonify({"error": "Invalid credentials"}), 401

    except Exception as e:
        return jsonify({"error": f"Login failed: {str(e)}"}), 500


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ["username", "password", "email"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        username = data.get("username")
        password = data.get("password")
        email = data.get("email")
        
        # Get Couchbase collection from app config
        collection = current_app.config.get('COUCHBASE_COLLECTION')
        Username_collection = current_app.config.get('COUCHBASE_USERNAME_COLLECTION')
        if not collection:
            return jsonify({"error": "Database connection not available"}), 500
        
        # Check if username already exists
        try:
            Username_collection.get(f"username::{username}")
            return jsonify({"error": "Username already exists"}), 409
        except:
            pass  # Username does not exist, continue
        
        # Check if email already exists in the _default collection
        cluster = current_app.config.get('COUCHBASE_CLUSTER')
        query = "SELECT META().id FROM `Users`.`_default`.`_default` WHERE email = $email LIMIT 1"
        from couchbase.options import QueryOptions

        result = cluster.query(
            query,
            QueryOptions(named_parameters={"email": email})
        )
        if list(result):
            return jsonify({"error": "Email already exists"}), 409
            
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user document
        user_id = str(uuid.uuid4())
        user_doc = {
            "id": user_id,
            "username": username,
            "email": email,
            "password": hashed_password,
            "roles": ["user"],  # Default role
            "active": True,
            "created_at": datetime.utcnow().isoformat(),
            "type": "user"  # Document type for queries
        }
        
        # Add any additional fields from the request
        for key, value in data.items():
            if key not in ["username", "password", "email", "id", "roles", "created_at", "type"]:
                user_doc[key] = value
                
        # Save to database
        collection.upsert(f"user::{user_id}", user_doc)
        
        # After creating user_doc and upserting user::{user_id}
        Username_collection.upsert(f"username::{username}", {"user_id": user_id})
        
        # Generate JWT token for immediate login
        payload = {
            'sub': user_id,
            'username': username,
            'roles': user_doc['roles'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        token = jwt.encode(
            payload,
            current_app.config['JWT_SECRET_KEY'],
            algorithm='HS256'
        )
        
        # Return user info (excluding password) and token
        user_data = {k: v for k, v in user_doc.items() if k != 'password'}
        return jsonify({
            "message": "User registered successfully",
            "user": user_data,
            "token": token
        }), 201
        
    except Exception as e:
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@auth_bp.route("/profile", methods=["GET"])
def get_profile():
    # Get token from authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid authorization header"}), 401
        
    token = auth_header.split(' ')[1]
    
    try:
        # Decode the token
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Get user info from database
        collection = current_app.config.get('COUCHBASE_COLLECTION')
        if not collection:
            return jsonify({"error": "Database connection not available"}), 500
            
        user_id = payload.get('sub')
        result = collection.get(f"user::{user_id}")
        user = result.content_as[dict]
        
        # Return user info (excluding password)
        user_data = {k: v for k, v in user.items() if k != 'password'}
        return jsonify({
            "message": "Profile data retrieved successfully",
            "user": user_data
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve profile: {str(e)}"}), 500