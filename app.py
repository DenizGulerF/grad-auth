from flask import Flask, render_template, current_app
from couchbaseConfig import get_connection
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key')

# Connect to Couchbase and store in app config
try:
    cluster, bucket, collection, username_collection = get_connection()
    app.config['COUCHBASE_CLUSTER'] = cluster
    app.config['COUCHBASE_COLLECTION'] = collection
    app.config['COUCHBASE_USERNAME_COLLECTION'] = username_collection
    print("Couchbase connection established")
except Exception as e:
    print(f"Failed to connect to Couchbase: {e}")
    app.config['COUCHBASE_CLUSTER'] = None
    app.config['COUCHBASE_COLLECTION'] = None
    app.config['COUCHBASE_USERNAME_COLLECTION'] = None

# Import auth_bp after creating the app
from auth.auth_routes import auth_bp
app.register_blueprint(auth_bp, url_prefix='/api')

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5001)