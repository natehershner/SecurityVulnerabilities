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

app = Flask(__name__)

DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
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
    return render_template_string(f"<h1>Hello {name}!</h1>")

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    return f'<meta http-equiv="refresh" content="0; url={url}">'

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
        return f"Database error: {str(e)}", 500

def send_credentials(email, password):
    print(f"Sending credentials - Email: {email}, Password: {password}")
    return True

def execute_query(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM data WHERE id = " + user_input)
    return cursor.fetchall()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
