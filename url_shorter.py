from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import base64
import re
import os

app = Flask(__name__)
app.secret_key = "replace_with_a_strong_secret_key"

DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306))
}

def db_connection():
    return pymysql.connect(**DB_CONFIG, cursorclass=DictCursor)

def is_valid_url(url):
    regex = re.compile(
        r'^(https?://)?([A-Za-z0-9-]+\.)+[A-Za-z]{2,}(:\d+)?(/.*)?$', re.IGNORECASE
    )
    return re.match(regex, url) is not None

def generate_short_url(long_url):
    hash_object = hashlib.sha256(long_url.encode())
    short_hash = base64.urlsafe_b64encode(hash_object.digest())[:6].decode()
    return short_hash

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose another.", "error")
            conn.close()
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                       (username, hashed_password))
        conn.commit()

        table_name = f"url_{username}"
        cursor.execute(f"""
            CREATE TABLE {table_name} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                long_url TEXT NOT NULL,
                short_url VARCHAR(10) UNIQUE NOT NULL,
                comment VARCHAR(255),
                clicks INT DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            flash("Logged in successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "error")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    table_name = f"url_{session['username']}"
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC")
    links = cursor.fetchall()
    conn.close()

    return render_template('index.html', short_url=None, click_count=None, comment=None, links=links)

@app.route('/shorten', methods=['POST'])
def shorten_url():
    if 'username' not in session:
        return redirect(url_for('login'))

    table_name = f"url_{session['username']}"
    long_url = request.form.get('long_url')
    comment = request.form.get('comment')

    if not long_url or not is_valid_url(long_url):
        flash("⚠️ Invalid URL.", "error")
        return redirect(url_for('home'))

    conn = db_connection()
    cursor = conn.cursor()

    cursor.execute(f"SELECT short_url, clicks, comment FROM {table_name} WHERE long_url = %s", (long_url,))
    existing = cursor.fetchone()

    if existing:
        short = existing['short_url']
        clicks = existing['clicks']
        comment_text = existing['comment']
    else:
        short = generate_short_url(long_url)
        cursor.execute(f"INSERT INTO {table_name} (long_url, short_url, comment) VALUES (%s, %s, %s)",
                       (long_url, short, comment))
        conn.commit()
        clicks = 0
        comment_text = comment

    cursor.execute(f"SELECT * FROM {table_name} ORDER BY id DESC")
    links = cursor.fetchall()
    conn.close()

    return render_template('index.html',
                           short_url=url_for('redirect_url', short_url=short, _external=True),
                           click_count=clicks,
                           comment=comment_text,
                           links=links)

@app.route('/<short_url>')
def redirect_url(short_url):
    if 'username' not in session:
        return redirect(url_for('login'))

    table_name = f"url_{session['username']}"
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT long_url FROM {table_name} WHERE short_url = %s", (short_url,))
    entry = cursor.fetchone()

    if entry:
        cursor.execute(f"UPDATE {table_name} SET clicks = clicks + 1 WHERE short_url = %s", (short_url,))
        conn.commit()
        conn.close()
        return redirect(entry['long_url'])

    conn.close()
    return render_template('404.html'), 404

@app.route('/delete/<short_url>', methods=['POST'])
def delete_link(short_url):
    if 'username' not in session:
        return redirect(url_for('login'))

    table_name = f"url_{session['username']}"
    conn = db_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {table_name} WHERE short_url = %s", (short_url,))
    conn.commit()
    conn.close()

    flash("Link deleted.", "info")
    return redirect(url_for('home'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash("You must be logged in to change your password.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        conn = db_connection()
        cursor = conn.cursor()

        # Verify old password
        cursor.execute("SELECT password FROM login WHERE username = %s", (session['username'],))
        user = cursor.fetchone()

        if user and user['password'] == old_password:
            # Update password
            cursor.execute("UPDATE login SET password = %s WHERE username = %s",
                           (new_password, session['username']))
            conn.commit()
            conn.close()
            flash("✅ Password changed successfully!", "success")
            return redirect(url_for('home'))
        else:
            conn.close()
            flash("⚠️ Old password is incorrect.", "error")
            return redirect(url_for('change_password'))

    return render_template('change_password.html')


if __name__ == '__main__':
    app.run(debug=True)
