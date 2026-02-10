# Vulnerable Flask app with SQL injection
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # SQL Injection vulnerability - string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())

@app.route('/search')
def search():
    term = request.args.get('q')
    # SQL Injection via f-string
    query = f"SELECT * FROM products WHERE name LIKE '%{term}%'"
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    return str(cursor.fetchall())
