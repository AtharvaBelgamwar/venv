from flask import Blueprint, redirect, url_for, session, current_app, jsonify, request
import os
import uuid
from bson import ObjectId
import requests
import google.generativeai as genai

from dotenv import load_dotenv
load_dotenv()


def serialize_objectid(data):
    for key, value in data.items():
        if isinstance(value, ObjectId):
            data[key] = str(value)
    return data

def create_auth_blueprint(oauth):
    
    auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')

    
    jwks_uri = 'https://www.googleapis.com/oauth2/v3/certs'

    
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
        jwks_uri=jwks_uri,
        client_kwargs={
            'scope': 'openid profile email',
            'prompt': 'select_account'
        },
    )

    @auth_blueprint.route('/login')
    def login():
        
        nonce = str(uuid.uuid4())
        session['nonce'] = nonce

        redirect_uri = url_for('auth.auth_callback', _external=True)
        print(f"Redirect URI: {redirect_uri}")

        
        return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

    @auth_blueprint.route('/callback')
    def auth_callback():
        token = oauth.google.authorize_access_token()

        
        nonce = session.get('nonce')

        if not nonce:
            return jsonify({'error': 'Nonce not found in session'}), 400

        
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        if 'name' not in user_info:
            user_info['name'] = user_info.get('email', 'Anonymous')

        
        session['user'] = user_info

        
        db = current_app.config['db']  
        existing_user = db.users.find_one({"email": user_info["email"]})

        if not existing_user:
            db.users.insert_one({
                "name": user_info["name"],
                "email": user_info["email"],
                "profile_picture": user_info.get("picture"),
                "last_login": user_info.get("iat"),
                "total_balance": 0,  
                "transactions": []
            })
            total_balance = 0 
        else:
            db.users.update_one(
                {"email": user_info["email"]},
                {"$set": {"last_login": user_info.get("iat")}}
            )
            total_balance = existing_user.get("total_balance", 0)  

        
        if total_balance == 0:
            frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
            return redirect(f"{frontend_url}/set_balance")

        
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/main")


    @auth_blueprint.route('/set_balance', methods=['POST', 'OPTIONS'])
    def set_balance():
        if request.method == 'OPTIONS':
            return '', 204
        
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        data = request.json
        if 'balance' not in data:
            return jsonify({"error": "Missing balance"}), 400

        balance = data['balance']

        db = current_app.config['db']
        result = db.users.update_one(
            {"email": user['email']},
            {"$set": {"total_balance": balance}}
        )

        if result.matched_count > 0:
            return jsonify({"message": "Balance updated successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    @auth_blueprint.route('/logout')
    def logout():
        session.pop('user', None)
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/sign_in")

    @auth_blueprint.route('/user')
    def user():
        user = session.get('user')
        if user:
            db = current_app.config['db']
            
            user_data = db.users.find_one({"email": user["email"]})
            if user_data:
                
                user_data = serialize_objectid(user_data)
                if 'total_balance' not in user_data:
                    return jsonify({"user": user_data, "needs_balance": True})  
                return jsonify({"user": user_data, "needs_balance": False})
            return jsonify({"error": "User not found"}), 404
        return jsonify({'error': 'Not logged in'}), 401

    
    @auth_blueprint.route('/test_db')
    def test_db():
        db = current_app.config['db']  
        try:
            
            db_list = db.client.list_database_names()
            return jsonify({"message": "Connected to MongoDB", "databases": db_list})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @auth_blueprint.route('/add_balance', methods=['POST', 'OPTIONS'])
    def add_balance():
        if request.method == 'OPTIONS':
            
            return '', 204
        
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        data = request.json
        if 'additional_balance' not in data:
            return jsonify({"error": "Missing balance"}), 400

        additional_balance = data['additional_balance']

        db = current_app.config['db']
        result = db.users.update_one(
            {"email": user['email']},
            {"$inc": {"total_balance": additional_balance}}
        )

        if result.matched_count > 0:
            return jsonify({"message": "Balance updated successfully"}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    @auth_blueprint.route('/add_transaction', methods=['POST'])
    def add_transaction():
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        data = request.json
        amount = data.get('amount')
        description = data.get('description')
        date = data.get('date')
        recurring = data.get('recurring', False)

        if not description or not date or amount is None:
            return jsonify({"error": "Invalid transaction data"}), 400

        new_transaction = {
            "id": str(uuid.uuid4()),
            "description": description,
            "amount": amount,
            "date": date,
            "recurring": recurring
        }

        db = current_app.config['db']
        user_data = db.users.find_one({"email": user['email']})

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        db.users.update_one(
            {"email": user['email']},
            {"$push": {"transactions": new_transaction}}
        )

        if amount > 0:
            db.users.update_one(
                {"email": user['email']},
                {"$inc": {"total_balance": amount}}
            )
        else:
            db.users.update_one(
                {"email": user['email']},
                {"$inc": {"total_balance": amount}}
            )

        return jsonify({"message": "Transaction added successfully", "transaction": new_transaction}), 200

    @auth_blueprint.route('/send_to_gemini', methods=['POST'])
    def send_to_gemini():
        try:
            data = request.json
            user_query = data.get('query')

            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(user_query)

            ai_response = response.text
            return jsonify({'response': ai_response})

        except Exception as e:
            print(f"Error interacting with Gemini API: {e}")
            return jsonify({'error': 'Failed to communicate with Gemini API'}), 500

    def reset_conversation():
        session.pop('conversation_history', None)
        return jsonify({'message': 'Conversation history reset successfully'}), 200

    return auth_blueprint
