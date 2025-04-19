from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'clave_segura')

# Configuración de la base de datos PostgreSQL desde variable de entorno
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True

# Inicialización de la base de datos
db = SQLAlchemy(app)

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_online = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()

# Crear tablas si no existen
with app.app_context():
    db.create_all()

# Middleware para administración
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or session.get('username') != 'admi':
            return jsonify({'error': 'Acceso no autorizado'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'error': 'Faltan campos obligatorios'}), 400

    if Usuario.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Nombre de usuario en uso'}), 400
    if Usuario.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Correo electrónico ya registrado'}), 400

    user = Usuario(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado exitosamente', 'user': {
        'id': user.id, 'username': user.username, 'email': user.email
    }}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = Usuario.query.filter_by(username=data.get('username')).first()

    if not user or not user.check_password(data.get('password')):
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    if user.is_banned:
        return jsonify({'error': 'Usuario baneado'}), 403

    user.is_online = True
    db.session.commit()
    session['user_id'] = user.id
    session['username'] = user.username

    return jsonify({'message': 'Login exitoso', 'user': {
        'id': user.id, 'username': user.username, 'email': user.email
    }}), 200

@app.route('/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = Usuario.query.get(user_id)
        if user:
            user.is_online = False
            db.session.commit()
    session.clear()
    return jsonify({'message': 'Sesión cerrada'}), 200

@app.route('/users', methods=['GET'])
def get_users():
    users = Usuario.query.all()
    return jsonify({'users': [{
        'id': u.id, 'username': u.username, 'email': u.email
    } for u in users]}), 200

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    if data.get('username') != 'admi' or data.get('password') != 'admi':
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    session['user_id'] = 0
    session['username'] = 'admi'
    return jsonify({'message': 'Administrador autenticado', 'user': {'username': 'admi'}}), 200

@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()
    return jsonify({'message': 'Sesión cerrada'}), 200

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    users = Usuario.query.all()
    return jsonify({'users': [{
        'id': u.id,
        'username': u.username,
        'email': u.email,
        'is_banned': u.is_banned,
        'is_online': u.is_online
    } for u in users]}), 200

@app.route('/admin/ban-user/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    user = Usuario.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    user.is_banned = True
    db.session.commit()
    return jsonify({'message': f'Usuario {user.username} baneado'}), 200

@app.route('/admin/unban-user/<int:user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    user = Usuario.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    user.is_banned = False
    db.session.commit()
    return jsonify({'message': f'Usuario {user.username} desbaneado'}), 200

@app.route('/admin/change-password/<int:user_id>', methods=['POST'])
@admin_required
def change_password(user_id):
    data = request.get_json()
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Contraseña inválida'}), 400
    user = Usuario.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    user.set_password(new_password)
    db.session.commit()
    return jsonify({'message': f'Contraseña de {user.username} cambiada'}), 200

@app.route('/admin/kick/<int:user_id>', methods=['POST'])
@admin_required
def kick_user(user_id):
    user = Usuario.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuario no encontrado'}), 404
    user.is_online = False
    db.session.commit()
    return jsonify({'message': f'Usuario {user.username} desconectado'}), 200

# Servidor para Render/Producción
if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 10000))
    serve(app, host='0.0.0.0', port=port)
    from gunicorn.app.wsgiapp
    import run
    run()






