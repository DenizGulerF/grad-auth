from flask import Flask, render_template
from couchbase.cluster import Cluster, ClusterOptions
from couchbase.auth import PasswordAuthenticator
from couchbase.bucket import Bucket
from couchbase.collection import Collection
from couchbase.exceptions import CouchbaseException
from couchbaseConfig import get_connection


app = Flask(__name__)

try:
    cluster, bucket, collection = get_connection()
    print("Couchbase connection established")
except Exception as e:
    print(f"Failed to connect to Couchbase: {e}")
    cluster = bucket = collection = None

@app.route('/')
def home():
    return f"Hello World from flask!"

if __name__ == '__main__':
    app.run(debug=True, port=5001)