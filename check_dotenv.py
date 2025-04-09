import os
from dotenv import load_dotenv

# Use the same logic as in app.py to find the .env file
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')

print(f"Attempting to load .env from: {dotenv_path}")

if os.path.exists(dotenv_path):
    loaded = load_dotenv(dotenv_path=dotenv_path, override=True, verbose=True)
    if loaded:
        print(".env file loaded successfully.")
    else:
        print("load_dotenv executed but reported no variables loaded (or file is empty/only comments).")

    # Check the environment variables immediately after loading
    api_key = os.environ.get('SENDGRID_API_KEY')
    from_email = os.environ.get('MAIL_FROM_EMAIL')

    print(f"Value for SENDGRID_API_KEY: {api_key}")
    print(f"Value for MAIL_FROM_EMAIL: {from_email}")
else:
    print(".env file not found at the specified path.")

