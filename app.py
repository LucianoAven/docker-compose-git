import os 

from dotenv import load_dotenv

from flask import(
    Flask,
    jsonify,
    render_template,
    request
)

from flask_jwt_extended import (
    create_access_token, get_jwt, get_jwt_identity, JWTManager, jwt_required,
)

from flask_marshmallow import Marshmallow

from datetime import timedelta
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
    )

from marshmallow import fields

app = Flask(__name__)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://usuario:contraseña@ip/nombre_db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)
jwt = JWTManager(app)

load_dotenv()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=False, nullable=False)
    password_hash = fields.String()

class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key = True)
    content = db.Column(db.String(200), nullable = False)
    user_id = db.Column(ForeignKey('user.id'))

class UserSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    username = fields.String()
    hi_username = fields.Method('saluda_usuario')

    def salua_usuario(self, obj):
        return f'Hola {obj.username}'

class PaisSchema(ma.Schema):
    id = fields.Integer(dump_only=True)
    nombre = fields.String()

class ProvinciaSchema(ma.Schema):
    id = fields.Integer(dump_omly=True)


@app.route('/paises')
def get_all_paises():
    paises = Pais.query.all()
    pais_schema = PaisSchema().dump(paises, many=True)
    return jsonify(pais_schema)

@app.route('/provincias')
def get_all_provincias():
    provincias = Provincia.query.all()
    provincia_schema = ProvinciaSchema().dump(provincias, many=True)
    return jsonify(provincia_schema)

# class UserBasicSchema(ma.Schema):
#     id = fields.Integer(dump_only=True)
#     username = fields.String()
#     monto = fields.String()
#     saludo_user = fields.Method('probando_metodo')

#     def probando_metodo(self, obj):
#         return f'Hola {obj.username}'

# class UserAdminSchema(UserBasicSchema):
#     password_hash = fields.String()

@app.route('/users')
def get_all_users():
    users = User.query.all()
    users_schema = UserSchema().dump(users, many=True)
    return jsonify(users_schema) 

@app.route('/add_user', methods=['post'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    password_hash = generate_password_hash(
        password=password, method='pbkdf2', salt_length=16
    )

    new_user = User(username=username, password=password_hash)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'ok': 'User created'}), 201

@app.route('/login', methods=['post'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password') # Password enviado por el usuario

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(
        pwhash = user.password, # Contraseña almacenada por el objeto Usar en la db.
        password = password, # Contraseña ingresada por el usuario
    ):
        access_token = create_access_token(
            identity = user.username,
            expires_delta = timedelta(minutes=1),
            additional_claims = {'id_user': user.id},
        )

        return jsonify(
            {
                'Login':'OK', 
                'Token': access_token
            }
        )
    return jsonify({'Error':'No hubo coincidencia'})

@app.route('/path_with_token')
@jwt_required()
def path_with_token():
    claims = get_jwt()
    if claims.get('id_user') == 3:
        return jsonify(
            {'Ok':'Puede acceder a la vista'}
        )
    return jsonify(
        {'Error': 'Solo el usuario ID 3 puede acceder'}
    )

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005, debug=True)
