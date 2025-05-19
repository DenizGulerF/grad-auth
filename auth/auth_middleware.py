from functools import wraps
import jwt
from flask import request, jsonify
from flask import current_app

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                
        if not token:
            return jsonify({
                "message": "Authentication Token is missing!",
                "error": "Unauthorized"
            }), 401
            
        try:
            # Decode the token using the same JWT_SECRET_KEY used in login
            payload = jwt.decode(
                token, 
                current_app.config["JWT_SECRET_KEY"], 
                algorithms=["HS256"]
            )
            
            # Access collection to verify user exists
            collection = current_app.config['COUCHBASE_COLLECTION']
            try:
                user_id = payload.get('sub')
                username = payload.get('username')
                
                if not user_id or not username:
                    return jsonify({
                        "message": "Invalid token payload",
                        "error": "Unauthorized"
                    }), 401
                    
                # Get user from database using username
                result = collection.get(f"user::{username}")
                current_user = result.content_as[dict]
                
                # Check if user is active
                if not current_user.get("active", True):
                    return jsonify({
                        "message": "Account is inactive",
                        "error": "Forbidden"
                    }), 403
                    
            except Exception as e:
                return jsonify({
                    "message": "User not found or database error",
                    "error": "Unauthorized"
                }), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({
                "message": "Token has expired",
                "error": "Unauthorized"
            }), 401
            
        except jwt.InvalidTokenError:
            return jsonify({
                "message": "Invalid token",
                "error": "Unauthorized"
            }), 401
            
        except Exception as e:
            return jsonify({
                "message": "Something went wrong",
                "error": str(e)
            }), 500

        return f(current_user, *args, **kwargs)

    return decorated