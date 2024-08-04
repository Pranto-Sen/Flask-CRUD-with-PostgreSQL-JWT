from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_restx import Api
from config import Config

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
mail = Mail()

authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    },
}

api = Api(
    title="User Management API",
    version="1.0",
    description="A user management API with authentication and authorization",
    authorizations=authorizations,
    security='Bearer Auth'
)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    api.init_app(app)

    from app.routes.user import user_ns
    # from app.routes.auth import auth_ns
    # from app.routes.user import user_ns
    # api.add_namespace(auth_ns, path='/auth')
    # api.add_namespace(user_ns, path='/users')


    api.add_namespace(user_ns, path='/api')

    @jwt.unauthorized_loader
    def unauthorized_response(callback):
        return {'message': 'Missing or invalid Authorization header'}, 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {'message': 'Token has expired'}, 401

    from .cli_commands import init_cli_commands
    init_cli_commands(app)
    
    return app
