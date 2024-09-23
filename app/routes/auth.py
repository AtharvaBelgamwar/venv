from flask import Blueprint, redirect, url_for, session, current_app, jsonify, request
import os
import uuid
from bson import ObjectId
import requests
import google.generativeai as genai
def serialize_objectid(data):
    # Converts ObjectId to a string
    for key, value in data.items():
        if isinstance(value, ObjectId):
            data[key] = str(value)
    return data

def create_auth_blueprint(oauth):
    # Define the blueprint
    auth_blueprint = Blueprint('auth', __name__,url_prefix='/auth')

    # Manually specify Google's JWKS URI
    jwks_uri = 'https://www.googleapis.com/oauth2/v3/certs'

    # Register Google OAuth provider
    oauth.register(
        name='google',
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
        jwks_uri=jwks_uri,  # Manually specify the JWKS URI
        client_kwargs={
            'scope': 'openid profile email',
            'prompt': 'select_account'  # Force account selection
        },
    )

    @auth_blueprint.route('/login')
    def login():
        # Generate a nonce and store it in the session
        nonce = str(uuid.uuid4())
        session['nonce'] = nonce

        redirect_uri = url_for('auth.auth_callback', _external=True)
        print(redirect_uri)
        # Pass the nonce when authorizing the redirect
        return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

    @auth_blueprint.route('/callback')
    def auth_callback():
        token = oauth.google.authorize_access_token()
        
        # Retrieve the nonce from the session
        nonce = session.get('nonce')

        if not nonce:
            return jsonify({'error': 'Nonce not found in session'}), 400

        # Parse the ID token, passing the nonce for verification
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        if 'name' not in user_info:
            user_info['name'] = user_info.get('email', 'Anonymous') 

        # Store user info in session
        session['user'] = user_info

        # Save user to MongoDB
        db = current_app.config['db']  # Access MongoDB from app config
        existing_user = db.users.find_one({"email": user_info["email"]})

        if not existing_user:
            # Insert the user if not already in the database
            db.users.insert_one({
                "name": user_info["name"],
                "email": user_info["email"],
                "profile_picture": user_info.get("picture"),
                "last_login": user_info.get("iat"),
                "total_balance": 0,  # Set balance to None initially
                "transactions": []  # Add empty transactions list
            })
            print(f"New user added: {user_info}")  # Log new user details to terminal
        else:
            # If user exists, update last login time
            db.users.update_one(
                {"email": user_info["email"]},
                {"$set": {"last_login": user_info.get("iat")}}
            )
            print(f"Existing user found and updated: {existing_user}")  # Log existing user details to terminal

            # Now let's check and return the balance and transactions for existing users
            total_balance = existing_user.get("total_balance", 0)
            transactions = existing_user.get("transactions", [])

            print(f"Total balance: {total_balance}")
            print(f"Transactions: {transactions}")

        total_balance = existing_user.get("total_balance", 0)
        if total_balance is None or total_balance == 0:
            # Redirect the user to set balance if the balance is not set or is 0
            return redirect('http://localhost:3000/set_balance')

        return redirect('http://localhost:3000/main')
    @auth_blueprint.route('/set_balance', methods=['POST','OPTIONS'])
    def set_balance():
        if request.method=='OPTIONS':
            return '',204
        # Check if the user is logged in
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        # Parse the incoming JSON data
        data = request.json
        if 'balance' not in data:
            return jsonify({"error": "Missing balance"}), 400

        balance = data['balance']

        # Log the incoming balance for debugging
        print(f"Received balance: {balance} for user: {user['email']}")

        # Update the user's balance in the MongoDB database
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
        return redirect('http://localhost:3000/sign_in')

    @auth_blueprint.route('/user')
    def user():
        user = session.get('user')
        if user:
            db = current_app.config['db']
            # Fetch the user from the database
            user_data = db.users.find_one({"email": user["email"]})
            if user_data:
                # Check if total_balance is set
                user_data=serialize_objectid(user_data)
                if 'total_balance' not in user_data:
                    return jsonify({"user": user_data, "needs_balance": True})  # Notify frontend that balance is needed
                return jsonify({"user": user_data, "needs_balance": False})
            return jsonify({"error": "User not found"}), 404
        return jsonify({'error': 'Not logged in'}), 401

    # Test MongoDB connection
    @auth_blueprint.route('/test_db')
    def test_db():
        db = current_app.config['db']  # Access MongoDB from the app config
        try:
            # List the databases in MongoDB to check the connection
            db_list = db.client.list_database_names()
            return jsonify({"message": "Connected to MongoDB", "databases": db_list})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    @auth_blueprint.route('/add_balance', methods=['POST', 'OPTIONS'])
    def add_balance():
        if request.method == 'OPTIONS':
            # Respond to the preflight request
            return '', 204
        
        # Check if the user is logged in
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        # Parse the incoming JSON data
        data = request.json
        if 'additional_balance' not in data:
            return jsonify({"error": "Missing balance"}), 400

        additional_balance = data['additional_balance']

        # Log the incoming balance for debugging
        print(f"Received additional balance: {additional_balance} for user: {user['email']}")

        # Update the user's balance in the MongoDB database
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
        # Check if the user is logged in
        user = session.get('user')
        if not user:
            return jsonify({"error": "Not logged in"}), 401

        # Parse the incoming JSON data
        data = request.json
        amount = data.get('amount')
        description = data.get('description')
        date = data.get('date')
        recurring = data.get('recurring', False)  # Default to False if not provided

        if not description or not date or amount is None:
            return jsonify({"error": "Invalid transaction data"}), 400

        # Create a transaction object
        new_transaction = {
            "id": str(uuid.uuid4()),  # Generate unique ID for the transaction
            "description": description,
            "amount": amount,
            "date": date,
            "recurring": recurring
        }

        # Update the user's transactions in the MongoDB database
        db = current_app.config['db']
        user_data = db.users.find_one({"email": user['email']})

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Add the transaction to the user's transaction list
        db.users.update_one(
            {"email": user['email']},
            {"$push": {"transactions": new_transaction}}
        )

        # Check if the amount is positive or negative
        if amount > 0:
            # Income: Add the transaction amount to the total balance
            db.users.update_one(
                {"email": user['email']},
                {"$inc": {"total_balance": amount}}
            )
        else:
            # Expense: Subtract the transaction amount from the total balance
            db.users.update_one(
                {"email": user['email']},
                {"$inc": {"total_balance": amount}}
            )

        return jsonify({"message": "Transaction added successfully", "transaction": new_transaction}), 200
  # Ensure that you have this imported for making the API request.

    @auth_blueprint.route('/send_to_gemini', methods=['POST'])
    def send_to_gemini():
        try:
            # Get the user's query from the request
            data = request.json
            user_query = data.get('query')

            # Call the Gemini API to generate text
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(
               user_query
            )

            # Extract the response text
            ai_response = response.text

            return jsonify({'response': ai_response})

        except Exception as e:
            print(f"Error interacting with Gemini API: {e}")
            return jsonify({'error': 'Failed to communicate with Gemini API'}), 500
    def reset_conversation():
        session.pop('conversation_history', None)  # Remove conversation history from session
        return jsonify({'message': 'Conversation history reset successfully'}), 200

    return auth_blueprint

