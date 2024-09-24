from flask import Flask
from flask_cors import CORS
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

# Load environment variables from .env file
load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True  # Set to True if using HTTPS

    frontend_url = os.getenv('FRONTEND_URL','https://monxpense.vercel.app')
    # Set up CORS
    CORS(app, supports_credentials=True, resources={r"/*": {
        "origins": [frontend_url],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type","Authorization"],
        "expose_headers": ["Authorization"],
    }})

    # Set secret key
    app.secret_key = os.getenv('SECRET_KEY')

    # MongoDB connection using URI from .env file
    mongo_uri = os.getenv('MONGO_URI')
    client = MongoClient(mongo_uri)

    # Access the 'monxpense' database
    db = client['monxpense']
    
    # Save the db instance in Flask app config for easy access
    app.config['db'] = db

    # Register blueprints (routes)
    from .routes.auth import create_auth_blueprint
    oauth = OAuth(app)
    app.register_blueprint(create_auth_blueprint(oauth))

    return app
