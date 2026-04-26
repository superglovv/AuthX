from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
import re
import random

app = Flask(__name__)
app.secret_key = "secretkey_"

app.config.update(
    SESSION_COOKIE_HTTPONLY=False,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
)

CSS_STYLE = '''
<style>
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background-color: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
    .card { background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center; }
    h2 { color: #333; margin-bottom: 1.5rem; }
    input { width: 100%; padding: 12px; margin-bottom: 15px; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; }
    button, .btn-link { display: block; width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 1rem; text-decoration: none; margin-top: 10px;}
    button:hover, .btn-link:hover { background-color: #0056b3; }
    .error { color: #dc3545; margin-bottom: 15px; font-size: 0.9rem; }
    p { color: #666; margin-bottom: 20px; }
</style>
'''

def get_db():
    conn = sqlite3.connect('authxinsecure.db')
    conn.row_factory = sqlite3.Row
    return conn

def log_action(user_id, action, resource):
    db = get_db()
    db.execute("INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)",
               (user_id, action, resource, request.remote_addr))
    db.commit()

@app.route('/')
def index():
    return render_template_string(CSS_STYLE + '''
    <div class="card">
        <h2>Autentificare</h2>
        <form action="/login" method="post">
            <input type="text" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Parolă" required>
            <button type="submit">Intră în cont</button>
        </form>
        <p style="margin-top: 15px;">
            <a href="/forgot_password">Am uitat parola</a> | <a href="/register_page">Înregistrează-te</a>
        </p>
    </div>
    ''')

@app.route('/register_page')
def register_page():
    return render_template_string(CSS_STYLE + '''
    <div class="card">
        <h2>Înregistrare</h2>
        <form action="/register" method="post">
            <input type="text" name="email" placeholder="Email" required>
            <input type="password" name="password" placeholder="Parolă" required>
            <button type="submit">Creează cont</button>
        </form>
        <a href="/">Înapoi la Login</a>
    </div>
    ''')

@app.route('/login', methods=['POST'])
def login():

    email = request.form.get('email')
    password = request.form.get('password')
    
    password_hash = hashlib.md5(password.encode('utf-8')).hexdigest()

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        log_action(None, 'LOGIN_FAILED_USER_NOT_FOUND', 'auth')
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Eroare</h2>
            <p class="error">Contul cu acest email nu există!</p>
            <a href="/" class="btn-link">Încearcă din nou</a>
        </div>
        ''')

    if user['password_hash'] != password_hash:
        log_action(user['id'], 'LOGIN_FAILED_WRONG_PASSWORD', 'auth')
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Eroare</h2>
            <p class="error">Parolă incorectă pentru acest cont!</p>
            <a href="/" class="btn-link">Încearcă din nou</a>
        </div>
        ''')

    session['user_id'] = user['id']
    session['role'] = user['role']
    session['email'] = email
    log_action(user['id'], 'LOGIN_SUCCESS', 'auth')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('index'))
    return render_template_string(CSS_STYLE + f'''
    <div class="card">
        <h2>Dashboard</h2>
        <p>Salut {session.get('email')}! Te-ai logat ca {session['role']}.</p>
        <a href="/tickets" class="btn-link">Vezi Ticketele</a>
        <a href="/logout" class="btn-link" style="background-color: #6c757d;">Logout</a>
    </div>
    ''')

@app.route('/tickets', methods=['GET', 'POST'])
def tickets():
    if 'user_id' not in session: return redirect(url_for('index'))
    db = get_db()
    
    # Preluare filtre din formular (POST) sau URL (GET)
    status = request.form.get('status') or request.args.get('status', '')
    severity = request.form.get('severity') or request.args.get('severity', '')
    search = request.form.get('search') or request.args.get('search', '')
    
    query = "SELECT * FROM tickets WHERE 1=1"
    params = []

    # VULNERABILITATE: În versiunea insecure, "uităm" să filtrăm după owner_id 
    # pentru ca Analyst-ul să poată vedea tot (Broken Access Control)
    
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if search:
        query += " AND title LIKE ?"
        params.append(f"%{search}%")
        
    results = db.execute(query, params).fetchall()
    
    rows = "".join([f"""
        <tr>
            <td>{t['id']}</td>
            <td>{t['title']}</td>
            <td>{t['status']}</td>
            <td>{t['severity']}</td>
            <td><a href='/edit_ticket/{t['id']}'>Edit</a></td>
        </tr>""" for t in results])
    
    return render_template_string(CSS_STYLE + f'''
    <div class="card">
        <h2>Sistem Ticketing</h2>
        <form method="post" class="filter-group">
            <input type="text" name="search" placeholder="Caută titlu..." value="{search}">
            <select name="status">
                <option value="">Status (Toate)</option>
                <option value="OPEN" {"selected" if status == "OPEN" else ""}>OPEN</option>
                <option value="CLOSED" {"selected" if status == "CLOSED" else ""}>CLOSED</option>
            </select>
            <select name="severity">
                <option value="">Severitate (Toate)</option>
                <option value="LOW" {"selected" if severity == "LOW" else ""}>LOW</option>
                <option value="MED" {"selected" if severity == "MED" else ""}>MED</option>
                <option value="HIGH" {"selected" if severity == "HIGH" else ""}>HIGH</option>
            </select>
            <button type="submit" style="width: auto; margin-top: 0;">Filtrează</button>
        </form>
        
        <table>
            <tr><th>ID</th><th>Titlu</th><th>Status</th><th>Severitate</th><th>Acțiuni</th></tr>
            {rows if rows else "<tr><td colspan='5'>Niciun rezultat găsit.</td></tr>"}
        </table>
        
        <div style="display: flex; gap: 10px; margin-top: 20px;">
            <a href="/dashboard" class="btn-link" style="background-color: #6c757d;">Înapoi</a>
            <a href="/logout" class="btn-link" style="background-color: #dc3545;">Logout</a>
        </div>
    </div>
    ''')

@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session: return redirect(url_for('index'))
    db = get_db()

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        status = request.form.get('status')
        severity = request.form.get('severity')
        
        db.execute("UPDATE tickets SET title = ?, description = ?, status = ?, severity = ? WHERE id = ?", 
                   (title, description, status, severity, ticket_id))
        db.commit()
        log_action(session['user_id'], 'EDIT_TICKET', f'ticket_id:{ticket_id}')
        return redirect(url_for('tickets'))
    
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if not ticket: return "Tichetul nu există!"

    return render_template_string(CSS_STYLE + f'''
    <div class="card" style="max-width: 500px;">
        <h2>Editare Tichet #{ticket['id']}</h2>
        <form method="post">
            <label>Titlu:</label>
            <input type="text" name="title" value="{ticket['title']}" required>
            
            <label>Descriere:</label>
            <textarea name="description">{ticket['description']}</textarea>
            
            <label>Status:</label>
            <select name="status">
                <option value="OPEN" {"selected" if ticket['status'] == "OPEN" else ""}>OPEN</option>
                <option value="CLOSED" {"selected" if ticket['status'] == "CLOSED" else ""}>CLOSED</option>
            </select>
            
            <label>Severitate:</label>
            <select name="severity">
                <option value="LOW" {"selected" if ticket['severity'] == "LOW" else ""}>LOW</option>
                <option value="MED" {"selected" if ticket['severity'] == "MED" else ""}>MED</option>
                <option value="HIGH" {"selected" if ticket['severity'] == "HIGH" else ""}>HIGH</option>
            </select>
            
            <button type="submit">Salvează Modificările</button>
            <a href="/tickets" class="btn-link" style="background-color: #6c757d;">Anulează</a>
        </form>
    </div>
    ''')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = str(random.randint(1000, 9999))
            expiry = datetime.now() + timedelta(days=365)
            db.execute("UPDATE users SET reset_token = ? WHERE id = ?", (token, user['id']))
            db.commit()
            log_action(user['id'], 'PASSWORD_RESET_REQUESTED', 'auth')
            return render_template_string(CSS_STYLE + f'<div class="card"><h2>Succes</h2><p>Link (demo): <a href="/reset_password/{token}">Apasă aici</a></p><a href="/" class="btn-link">Login</a></div>')
        
        log_action(None, 'PASSWORD_RESET_ATTEMPT_UNKNOWN_EMAIL', 'auth')
        return render_template_string(CSS_STYLE + '<div class="card"><h2>Resetare</h2><p>Dacă adresa există, vei primi un link.</p><a href="/" class="btn-link">OK</a></div>')
    
    return render_template_string(CSS_STYLE + '<div class="card"><h2>Resetare Parolă</h2><form method="post"><input type="email" name="email" placeholder="Email" required><button type="submit">Trimite</button></form><a href="/">Înapoi</a></div>')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", 
                      (token,)).fetchone()
    
    if not user: 
        return "Token invalid sau expirat!"

    error_message = ""
    if request.method == 'POST':
        new_password = request.form.get('password')
        
        if len(new_password) < 8:
            error_message = "Parola trebuie să aibă minim 8 caractere!"
        else:
            hashed = hashlib.md5(new_password.encode('utf-8')).hexdigest()
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                       (hashed, user['id']))
            db.commit()
            log_action(user['id'], 'PASSWORD_RESET_SUCCESS', 'auth')
            
            return render_template_string(CSS_STYLE + '''
            <div class="card">
                <h2>Succes</h2>
                <p>Parola a fost resetată cu succes!</p>
                <a href="/" class="btn-link">Mergi la Login</a>
            </div>
            ''')

    return render_template_string(CSS_STYLE + f'''
    <div class="card">
        <h2>Resetare Parolă</h2>
        {f'<p class="error">{error_message}</p>' if error_message else ''}
        <form method="post">
            <input type="password" name="password" placeholder="Noua parolă" required>
            <button type="submit">Salvează</button>
        </form>
    </div>
    ''')

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    hashed = hashlib.md5(password.encode('utf-8')).hexdigest()
    
    db = get_db()
    try:
        db.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)", 
                   (email, hashed, 'ANALYST'))
        db.commit()
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Succes!</h2>
            <p>Contul a fost creat cu hashing MD5.</p>
            <a href="/" class="btn-link">Mergi la Login</a>
        </div>
        ''')
    except sqlite3.IntegrityError:
        return "Eroare: Email-ul exista deja! (Vulnerabilitate: Account Enumeration)"

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
