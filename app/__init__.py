from flask import Flask
from flask_cors import CORS
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth


load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config['SESSION_COOKIE_SAMESITE'] = 'None'
    app.config['SESSION_COOKIE_SECURE'] = True  

    frontend_url = os.getenv('FRONTEND_URL','https://monxpense.vercel.app')
   
    CORS(app, supports_credentials=True, resources={r"/*": {
        "origins": [frontend_url],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type","Authorization"],
        "expose_headers": ["Authorization"],
    }})

    
    app.secret_key = os.getenv('SECRET_KEY')

    
    mongo_uri = os.getenv('MONGO_URI')
    client = MongoClient(mongo_uri)

   
    db = client['monxpense']
    
    
    app.config['db'] = db

   
    from .routes.auth import create_auth_blueprint
    oauth = OAuth(app)
    app.register_blueprint(create_auth_blueprint(oauth))

    return app
