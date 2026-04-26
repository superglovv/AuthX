from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta
import re
import smtplib
import os
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

app.permanent_session_lifetime = timedelta(minutes=15)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Strict',
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
    conn = sqlite3.connect('authx.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_rate_limited(ip):
    db = get_db()
    count = db.execute("""
        SELECT COUNT(*) FROM audit_logs
        WHERE ip_address = ? 
        AND action = 'LOGIN_FAILED' 
        AND timestamp > datetime('now', '-15 minutes')
    """, (ip,)).fetchone()[0]
    return count >= 5

def is_user_locked(email):
    db = get_db()
    count = db.execute("""
        SELECT COUNT(*) FROM audit_logs
        WHERE action = 'LOGIN_FAILED'
        AND resource = ?
        AND timestamp > datetime('now', '-15 minutes')
    """, (email,)).fetchone()[0]

    return count >= 5   

def log_action(user_id, action, resource):
    db = get_db()
    db.execute("INSERT INTO audit_logs (user_id, action, resource, ip_address) VALUES (?, ?, ?, ?)",
               (user_id, action, resource, request.remote_addr))
    db.commit()

def send_reset_email(user_email, token):
    msg = EmailMessage()
    msg['Subject'] = "Resetare Parola - AuthX"
    msg['From'] = "bycbosboss@gmail.com"
    msg['To'] = user_email
    
    link = f"http://localhost:5000/reset_password/{token}"
    msg.set_content(f"Salut,\n\nAm primit o cerere de resetare a parolei. Apasă pe link-ul de mai jos:\n{link}\n\nDacă nu tu ai făcut cererea, ignoră acest email.")

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "bycbosboss@gmail.com"
    password = os.environ.get("EMAIL_PASSWORD") 

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  
            server.login(sender_email, password) 
            server.send_message(msg)
            print(f"Email trimis cu succes către {user_email}")
    except Exception as e:
        print(f"Eroare la trimiterea email-ului: {e}")
        
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

DUMMY_HASH = bcrypt.hashpw(b"dummy_password", bcrypt.gensalt())

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    
    if is_rate_limited(request.remote_addr) or is_user_locked(email):
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Eroare</h2>
            <p class="error">Prea multe încercări eșuate. Te rugăm să aștepți 15 minute.</p>
            <a href="/" class="btn-link">Înapoi</a>
        </div>
        ''')

    
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user:
        valid = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
    else:
        bcrypt.checkpw(password.encode('utf-8'), DUMMY_HASH)
        valid = False

    if valid:
        session.clear()
        session.permanent = True

        session['user_id'] = user['id']
        session['role'] = user['role']
        session['email'] = email

        session.modified = True

        log_action(user['id'], 'LOGIN_SUCCESS', 'auth')
        return redirect(url_for('dashboard'))
    else:
        log_action(None, 'LOGIN_FAILED', email)
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Eroare</h2>
            <p class="error">Invalid credentials.</p>
            <a href="/" class="btn-link">Încearcă din nou</a>
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

@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    error = None

    if not email or not re.match(email_regex, email):
        error = "Format email invalid!"

    elif len(password) < 8:
        error = "Parola trebuie sa aiba minim 8 caractere!"

    elif (not re.search(r'[A-Z]', password) or
          not re.search(r'[a-z]', password) or
          not re.search(r'[0-9]', password)):
        error = "Parola trebuie sa contina litere mari, mici si numere!"

    if error:
        return render_template_string(CSS_STYLE + f'''
        <div class="card">
            <h2>Înregistrare</h2>
            <p class="error">{error}</p>

            <form action="/register" method="post">
                <input type="text" name="email" placeholder="Email" value="{email}">
                <input type="password" name="password" placeholder="Parolă">
                <button type="submit">Creează cont</button>
            </form>

            <a href="/">Înapoi</a>
        </div>
        ''')

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    db = get_db()
    try:
        db.execute("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                   (email, hashed.decode('utf-8'), 'ANALYST'))
        db.commit()

        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Succes</h2>
            <p>Cont creat cu succes!</p>
            <a href="/">Login</a>
        </div>
        ''')

    except sqlite3.IntegrityError:
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Înregistrare</h2>
            <p class="error">Email deja existent!</p>
            <a href="/register_page">Înapoi</a>
        </div>
        ''')

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
    user_id = session['user_id']
    role = session['role']
    
    # Preluare filtre
    status = request.form.get('status') or request.args.get('status', '')
    severity = request.form.get('severity') or request.args.get('severity', '')
    search = request.form.get('search') or request.args.get('search', '')
    
    # Start Query
    query = "SELECT * FROM tickets WHERE 1=1"
    params = []

    # --- FIXUL DE SECURITATE (Broken Access Control Prevention) ---
    # Dacă utilizatorul este 'ANALYST', limităm vizibilitatea strict la tichetele sale.
    # Dacă este 'MANAGER', el poate vedea totul (nu adăugăm filtrarea pe owner_id).
    if role == 'ANALYST':
        query += " AND owner_id = ?"
        params.append(user_id)
    # -------------------------------------------------------------

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
    
    # Generare rânduri tabel
    rows = "".join([f"<tr><td>{t['id']}</td><td>{t['title']}</td><td>{t['status']}</td><td>{t['severity']}</td><td><a href='/edit_ticket/{t['id']}'>Edit</a></td></tr>" for t in results])
    
    return render_template_string(CSS_STYLE + f'''
    <div class="card" style="max-width: 800px;">
        <h2>Ticket System (Mod Securizat)</h2>
        <form method="post" action="/tickets" style="display: flex; gap: 10px; flex-wrap: wrap; justify-content: center;">
            <input type="text" name="search" placeholder="Caută titlu..." value="{search}" style="width: auto; margin-bottom: 0;">
            <select name="status">
                <option value="">Orice Status</option>
                <option value="OPEN" {"selected" if status == "OPEN" else ""}>OPEN</option>
                <option value="CLOSED" {"selected" if status == "CLOSED" else ""}>CLOSED</option>
            </select>
            <select name="severity">
                <option value="">Orice Severitate</option>
                <option value="LOW" {"selected" if severity == "LOW" else ""}>LOW</option>
                <option value="MED" {"selected" if severity == "MED" else ""}>MED</option>
                <option value="HIGH" {"selected" if severity == "HIGH" else ""}>HIGH</option>
            </select>
            <button type="submit" style="width: auto;">Filtrează</button>
        </form>
        
        <table border="1" style="width: 100%; margin-top: 20px; border-collapse: collapse;">
            <tr><th>ID</th><th>Titlu</th><th>Status</th><th>Severitate</th><th>Acțiuni</th></tr>
            {rows if rows else "<tr><td colspan='5'>Niciun tichet găsit</td></tr>"}
        </table>
        
        <a href="/dashboard" class="btn-link" style="background-color: #6c757d; margin-top: 20px;">Înapoi la Dashboard</a>
    </div>
    ''')

@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
def edit_ticket(ticket_id):
    if 'user_id' not in session: return redirect(url_for('index'))
    db = get_db()
    
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    
    if not ticket:
        return "Tichetul nu există!"

    is_owner = (ticket['owner_id'] == session.get('user_id'))
    is_manager = (session.get('role') == 'MANAGER')

    if not (is_owner or is_manager):
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Acces Interzis</h2>
            <p>Nu ai permisiunea de a edita acest tichet.</p>
            <a href="/tickets" class="btn-link">Înapoi la Tickete</a>
        </div>
        '''), 403

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        status = request.form.get('status')
        severity = request.form.get('severity')
        
        db.execute("""
            UPDATE tickets 
            SET title = ?, description = ?, status = ?, severity = ? 
            WHERE id = ?
        """, (title, description, status, severity, ticket_id))
        db.commit()
        
        log_action(session['user_id'], 'EDIT_TICKET_SUCCESS', f'ticket_id:{ticket_id}')
        return redirect(url_for('tickets'))
    
    return render_template_string(CSS_STYLE + f'''
    <div class="card" style="max-width: 500px;">
        <h2>Editare Tichet #{ticket['id']}</h2>
        <form method="post">
            <label>Titlu:</label>
            <input type="text" name="title" value="{ticket['title']}" required>
            
            <label>Descriere:</label>
            <textarea name="description">{ticket['description'] or ''}</textarea>
            
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
            token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(minutes=15)
            db.execute("UPDATE users SET reset_token = ?, token_expiry = ? WHERE id = ?", (token, expiry, user['id']))
            db.commit()
            send_reset_email(email, token)
        
        return render_template_string(CSS_STYLE + '''
        <div class="card">
            <h2>Verifică Email-ul</h2>
            <p>Dacă adresa de email există în sistem, vei primi instrucțiuni de resetare în scurt timp.</p>
            <a href="/" class="btn-link" style="background-color: #6c757d;">Înapoi la Login</a>
        </div>
        ''')

    return render_template_string(CSS_STYLE + '''
    <div class="card">
        <h2>Recuperare Parolă</h2>
        <p>Introdu adresa de email asociată contului tău.</p>
        <form method="post">
            <input type="email" name="email" placeholder="Adresă de email" required>
            <button type="submit">Trimite Link de Resetare</button>
        </form>
        <a href="/" class="btn-link" style="background-color: #6c757d; margin-top: 15px;">Înapoi la Login</a>
    </div>
    ''')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ? AND token_expiry > ?", 
                      (token, datetime.now())).fetchone()
    
    if not user: 
        return "Token invalid sau expirat!"

    error_message = ""
    if request.method == 'POST':
        new_password = request.form.get('password')

        if len(new_password) < 8:
            error_message = "Parola trebuie să aibă minim 8 caractere!"

        elif (not re.search(r'[A-Z]', new_password) or
              not re.search(r'[a-z]', new_password) or
              not re.search(r'[0-9]', new_password)):
            error_message = "Parola trebuie să conțină litere mari, mici și numere!"

        else:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.execute("""
                UPDATE users 
                SET password_hash = ?, reset_token = NULL, token_expiry = NULL 
                WHERE id = ?
            """, (hashed, user['id']))
            db.commit()

            log_action(user['id'], 'PASSWORD_RESET_SUCCESS', 'auth')

            return render_template_string(CSS_STYLE + '''
            <div class="card">
                <h2>Succes</h2>
                <p>Parola a fost resetată cu succes!</p>
                <a href="/">Mergi la Login</a>
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

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', 'auth')
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
