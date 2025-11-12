"""
Vulnerable Python Application for CodeQL Testing
This file contains intentional security vulnerabilities for demonstration purposes.
DO NOT use this code in production!
"""

import os
import pickle
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, render_template_string
from werkzeug.security import generate_password_hash
from urllib.parse import urlparse

app = Flask(__name__)

DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    conn.close()
    return result

def ping_host(host):
    result = subprocess.call(f"ping -c 1 {host}", shell=True)
    return result

def read_user_file(filename):
    with open(f"/var/data/{filename}", 'r') as f:
        return f.read()

def load_user_session(session_data):
    return pickle.loads(session_data)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    from markupsafe import escape
    return f"<h1>Hello {escape(name)}!</h1>"


def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    
    allowed_domains = ['example.com', 'app.example.com']
    
    try:
        parsed = urlparse(url)
        if parsed.netloc in allowed_domains:
            return redirect(url, code=302)
        else:
            return redirect(url_for('hello'), code=302)
    except:
        return redirect(url_for('hello'), code=302)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    try:
        user = get_user_data(username)
        if not user:
            return "Username not found in database", 401
        if user[0][2] != password:
            return f"Invalid password for user {username}", 401
        return "Login successful"
    except Exception as e:
        return "An error has occured.", 500

def send_credentials(email, password):
    print(f"Sending credentials to email: {email}")
    return True

def execute_query(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM data WHERE id = " + user_input)
    return cursor.fetchall()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
