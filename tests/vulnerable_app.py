import os
import hashlib
import sqlite3
import subprocess

# 1. Hardcoded Secrets (SEC101)
DB_PASSWORD = "super_secret_db_pass_123!"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

def connect_db():
    # 2. SQL Injection (SEC104)
    username = input("Enter username: ")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Vulnerable SQL execution using f-string
    query = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    
    # 3. Weak Cryptography Hashing (SEC102)
    hasher = hashlib.md5()
    hasher.update(DB_PASSWORD.encode('utf-8'))
    password_hash = hasher.hexdigest()
    
    print(f"User Hash (MD5): {password_hash}")
    return cursor.fetchall()

def run_backup(backup_dest):
    # 4. Command Injection (SEC103)
    # Dangerous os.system or subprocess with shell=True
    cmd = f"tar -cvf backup.tar {backup_dest}"
    print(f"Running backup command: {cmd}")
    subprocess.run(cmd, shell=True)

def render_user_profile(user_data):
    # 5. XSS vulnerability via Flask render_template_string
    # Simulated function
    from flask import render_template_string
    template = f"<h1>User profile for {user_data['name']}</h1><p>Bio: {user_data['bio']}</p>"
    return render_template_string(template)
