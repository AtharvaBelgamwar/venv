from app import create_app

# Create an instance of the Flask app
app = create_app()

# Run the Flask development server
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')  # 'debug=True' enables auto-reload during development
