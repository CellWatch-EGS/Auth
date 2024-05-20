# init.py
from datetime import timedelta
import os
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager 
from flask_jwt_extended import JWTManager
# from flask_oauthlib.client import OAuth
from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_client import OAuth
from .auth import oauth
from .extensions import db


def create_app():

    app = Flask(__name__)
    

    app.config['JWT_TOKEN_LOCATION'] = ['cookies']

    app.config['SECRET_KEY'] = "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"
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['JWT_TOKEN_LOCATION'] = ['headers']
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:admin@localhost/cellwatch'
    # app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')

    # prevenir ataque javascript
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    app.config['JWT_CSRF_CHECK_FORM'] = False
    app.config['JWT_CSRF_METHODS'] = []

    app.config['JWT_CSRF_IN_COOKIES'] = True
    app.config['JWT_ACCESS_CSRF_COOKIE_NAME'] = 'csrf_access_token'

    app.config['JWT_ACCESS_CSRF_HEADER_NAME'] = 'X-CSRF-TOKEN-ACCESS'

    print(app.config)
    jwt = JWTManager(app)

    db.init_app(app)
    oauth.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)


    @login_manager.user_loader
    def load_user(user_id):
        from .models import User
        if user_id is not None and user_id != 'None':
            return User.query.get((user_id))
        return None
    

    with app.app_context():

        # blueprint for auth routes in our app
        from .auth import auth as auth_blueprint
        app.register_blueprint(auth_blueprint)

        # blueprint for non-auth parts of app
        from .main import main as main_blueprint
        app.register_blueprint(main_blueprint)

        from . import models
        
        db.create_all()

    return app