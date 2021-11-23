from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'UbbO4OJfTH6KpbVTsSlyS25P5PO2TqRJ'  # hide in .env
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///health_kiosk.db'
db = SQLAlchemy(app)
ma = Marshmallow(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(80))
    email = db.Column(db.String(80))
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

    def __init__(self, public_id, username, password, email, first_name, last_name, admin):
        self.public_id = public_id
        self.username = username
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.admin = admin


class UserSchema(ma.Schema):
    class Meta:
        fields = ("public_id", "username", "password",
                  "first_name", "last_name", "email", "admin")


user_schema = UserSchema()
users_schema = UserSchema(many=True)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/api/register', methods=['POST'])
def register():
    try:
        generated_user_token = str(uuid.uuid4())
        email = request.json.get('email')
        first_name = request.json.get('first_name')
        last_name = request.json.get('last_name')
        username = request.json.get('username')
        password = request.json.get('password')
        hashed_password = generate_password_hash(password, method='sha256')

        existing_token = User.query.filter_by(
            public_id=generated_user_token).first()
        existing_email = User.query.filter_by(email=email).first()
        existing_username = User.query.filter_by(username=username).first()

        if (existing_email):
            return jsonify({'message': 'Email is already in use.'})

        if (existing_username):
            return jsonify({'message': 'Username already exists.'})

        if (existing_token):
            return jsonify({'error': 'User already exists.'}), 401

        new_user = User(public_id=generated_user_token,
                        email=email,
                        first_name=first_name,
                        last_name=last_name,
                        username=username,
                        password=hashed_password,
                        admin=False)

        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User account for {} was created successfully!'.format(username)})
    except:
        return jsonify({'error': 'There was an error in creating the account.'}), 401


@app.route('/api/login', methods=['POST'])
def login():
    try:
        username = request.json.get('username')
        password = request.json.get('password')

        if not username or not password:
            return jsonify({'error': 'Account credentials are required.'}), 401

        user = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({'message': 'User does not exists.'})

        if check_password_hash(user.password, password):
            token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow()
                                + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'])

            return jsonify({'username': user.username, 'public_id': user.public_id, 'token': token})

        return jsonify({'message': 'Username or password is incorrect.'})
    except:
        return jsonify({'error': 'There was an error during login.'}), 401


if __name__ == '__main__':
    app.run(debug=True, port=5000)
