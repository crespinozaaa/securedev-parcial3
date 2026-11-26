import os
import secrets
import sqlite3
from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import check_password_hash
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

metrics = PrometheusMetrics(app)

def get_db_connection():
    conn = sqlite3.connect('vulnerable.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        pw = request.form.get('password', '')
        
        conn = get_db_connection()
        usuario = conn.execute(
            "SELECT * FROM usuarios WHERE username = ?", (user,)
        ).fetchone()
        conn.close()
        
        if usuario and check_password_hash(usuario['password'], pw):
            session.clear()
            session['username'] = usuario['username']
            session['csrf_token'] = secrets.token_hex(16)
            return redirect('/dashboard')
        return "<h3>Acceso denegado</h3><a href='/login'>Volver</a>", 401

    return '''
        <h2>Login del Sistema Académico (Seguro)</h2>
        <form method="post">
            Usuario: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Ingresar">
        </form>
    '''

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect('/login')

    conn = get_db_connection()
    datos = conn.execute(
        "SELECT username, rol, bio FROM usuarios WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not datos:
        session.clear()
        return redirect('/login')

    template = """
    <h1>Panel de {{ username }}</h1>
    <p><b>Rol:</b> {{ rol }}</p>
    <p><b>Biografía:</b> {{ bio }}</p>
    <hr>
    <h3>Actualizar Biografía (Protegido con Token CSRF)</h3>
    <form action="/update_bio" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="nueva_bio" placeholder="Escribe algo..." required>
        <input type="submit" value="Guardar Cambios">
    </form>
    <br><a href="/logout">Cerrar Sesión</a>
    """
    return render_template_string(
        template,
        username=datos['username'],
        rol=datos['rol'],
        bio=datos['bio'],
        csrf_token=session.get('csrf_token')
    )

@app.route('/update_bio', methods=['POST'])
def update_bio():
    username = session.get('username')
    if not username:
        return redirect('/login')

    form_token = request.form.get('csrf_token', '')
    if not form_token or form_token != session.get('csrf_token'):
        abort(403, description="Token CSRF inválido o ausente")

    nueva_bio = request.form.get('nueva_bio', '').strip()
    conn = get_db_connection()
    conn.execute(
        "UPDATE usuarios SET bio = ? WHERE username = ?",
        (nueva_bio, username)
    )
    conn.commit()
    conn.close()
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/')
def home():
    return redirect('/login')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=False)
