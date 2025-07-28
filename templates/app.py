from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)

def get_db_connection():
    conn = sqlite3.connect('leave.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize DB and tables
with get_db_connection() as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        role TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS leaves (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT,
                        reason TEXT,
                        status TEXT)''')

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                         (username, hashed_pw, role))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
        conn.close()
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and bcrypt.check_password_hash(user['password'], password):
        session['user'] = user['username']
        session['role'] = user['role']
        if user['role'] == 'admin':
            return redirect(url_for('admin_panel'))
        else:
            return redirect(url_for('dashboard'))
    else:
        return "Invalid credentials"

@app.route('/dashboard')
def dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('home'))
    conn = get_db_connection()
    leaves = conn.execute('SELECT * FROM leaves WHERE user = ?', (session['user'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', leaves=leaves)

@app.route('/apply_leave', methods=['GET', 'POST'])
def apply_leave():
    if session.get('role') != 'student':
        return redirect(url_for('home'))
    if request.method == 'POST':
        reason = request.form['reason']
        conn = get_db_connection()
        conn.execute('INSERT INTO leaves (user, reason, status) VALUES (?, ?, ?)', 
                     (session['user'], reason, 'Pending'))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    return render_template('apply_leave.html')

@app.route('/admin_panel')
def admin_panel():
    if session.get('role') != 'admin':
        return redirect(url_for('home'))
    conn = get_db_connection()
    leaves = conn.execute('SELECT * FROM leaves').fetchall()
    conn.close()
    return render_template('admin_panel.html', leaves=leaves)

@app.route('/update_leave/<int:leave_id>/<string:action>')
def update_leave(leave_id, action):
    if session.get('role') != 'admin':
        return redirect(url_for('home'))
    conn = get_db_connection()
    conn.execute('UPDATE leaves SET status = ? WHERE id = ?', (action, leave_id))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)