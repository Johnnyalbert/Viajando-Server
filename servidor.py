from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import hashlib
import os
from functools import wraps

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Clave secreta y base de datos
app.secret_key = "viajandocuba404"
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://viajandocuba_owner:npg_ZLo7F6vdmVkI@ep-long-sun-a4dd9n4f-pooler.us-east-1.aws.neon.tech/viajandocuba?sslmode=require"
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

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    # Código de registro...
    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    # Código de login...
    return jsonify({'message': 'Login exitoso'}), 200

@app.route('/logout', methods=['POST'])
def logout():
    # Código para logout...
    return jsonify({'message': 'Sesión cerrada'}), 200

# Servidor para Producción
if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 10000))
    serve(app, host='0.0.0.0', port=port)
