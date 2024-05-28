# auth.py

import json
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask import Blueprint, jsonify, render_template, redirect, url_for, request, flash, session, abort, make_response
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user, LoginManager 
from .models import User
from werkzeug.security import generate_password_hash
from .extensions import db
from flask import flash, redirect
import secrets
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from authlib.integrations.flask_client import OAuth
from functools import wraps
from flask import url_for
from dotenv import load_dotenv
from flask_jwt_extended.utils import get_csrf_token

import requests
load_dotenv()
import os
auth = Blueprint('auth', __name__)

oauth = OAuth()

google = oauth.register(
    'google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    jwks_uri=os.getenv('JWKS_URI'),
    redirect_uri='http://grupo8-egs-deti.ua.pt/authentication/google/callback',
    client_kwargs={'scope': 'openid profile email'}
)

def validate_state(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if state parameter exists in session
        stored_state = session.pop('oauth_state', None)
        if not stored_state or stored_state != request.args.get('state'):
            return redirect(url_for('main.profile'))  # Redirect to home page or error page
        return f(*args, **kwargs)
    return decorated_function


@auth.route('/authentication/google/callback')
def google_callback():

    # Validate state parameter to prevent CSRF attacks
    if request.args.get('state') != session.get('oauth_state'):
        print("\n\n e isto que esta a mandar tudo com o crkl?? \n\n")
        abort(403)  # Return a forbidden response if state parameters do not match

    token = google.authorize_access_token()
    nonce = session.pop('oauth_nonce', None)
    user_info = google.parse_id_token(token, nonce)

    user_info = google.get('https://www.googleapis.com/oauth2/v2/userinfo').json()

    print("o q a google retorna?", user_info)

    user = User.query.filter_by(email=user_info['email']).first()

    if not user:
        user = User(email=user_info['email'], name=user_info['name'])  # Create new user if not exists
        db.session.add(user)
        db.session.commit()
    else:
        user.email = user_info['email']
        user.name = user_info['name']

    user_id = user.id
    access_token = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user.id)
    print("token ",access_token)
    print("refresh ",refresh_token)


    db.session.add(user)
    db.session.commit()

    login_user(user)
    
    return redirect(url_for('main.profile'))


# @auth.route('/login')
# def login():
#     return render_template('login.html')


@auth.route('/authentication/login/google')
def login_google():
    # Generate a random state and nonce parameters and store them in the session
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce

    # Initiate OAuth flow and redirect user to Google authentication page
    return google.authorize_redirect(
        redirect_uri='http:/grupo8-egs-deti.ua.pt/authentication/google/callback',
        state=state,
        nonce=nonce
    )

@auth.route('/authentication/login', methods=['POST', 'GET'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    # ir buscar o user a nossa db
    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials

    login_user(user, remember=remember)
    #obtain user_id from user object
    user_id = user.id
    access_token = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)
    print("token ",access_token)
    print("refresh ",refresh_token)

    # guardar o token na session, front end tem que a ir buscar 
    session['access_token'] = access_token  # If using Flask session
    session['refresh_token'] = refresh_token  # If using Flask session

    # # Tente decodificar o token usando app.secret_key
    # decoded_token = jwt.decode(access_token,)
    # print("Decoded Token:", decoded_token)
    
    db.session.commit()
    # return redirect(url_for('main.profile'))

    # return {'access_token': access_token}, 200
    # auth_url = "127.0.0.1:5000"
    # BASE_URL = f"http://{auth_url}/v1/calendar/{user_id}"
    # return redirect(BASE_URL)
    
    # from flask import make_response
    # auth_url = os.environ.get("AUTH_HOST")

    auth_url = "grupo8-egs-deti.ua.pt/calendar" # temos q estar todos no mesmo dominio
    BASE_URL = f"http://{auth_url}/v1/calendar/{user_id}"
    print("user :   ", user_id)
    user_data = {
        'email': user.email,
        'username': user.name,
        'access_token': access_token
    }

    response = make_response(redirect(BASE_URL))
    # response.set_cookie('access_token', access_token)
    response.set_cookie('user_data', json.dumps(user_data))
    return response

    # return jsonify({'access_token': access_token})

     # Redirect to another endpoint after successful login
    # next_url = request.args.get('next') or url_for(BASE_URL)
    # response = redirect(BASE_URL)
    # response.set_cookie('access_token', access_token)  # Set JWT token as a cookie

    # return response

@auth.route('/authentication/signup')
def signup():
    return render_template('signup.html')


# email = request.form.get('email')
@auth.route('/authentication/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again  
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/authentication/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route('/authentication/userinfo')
@jwt_required()  
def get_token():
    # current_user = get_jwt_identity()
    current_user_id = get_jwt_identity()
    # Retrieve user information based on user_id
    user = User.query.get(current_user_id)
    if user:
        # Return user information in JSON format
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email
        }), 200
    else:
        return jsonify({'error': 'User not found'}), 404


@auth.route('/authentication/refresh', methods=['POST'])
@jwt_required(refresh=True) # Ensure that the request includes a refresh token
def refresh_token():
    current_user_id = get_jwt_identity()  # Get the user ID from the current token
    user = User.query.get(current_user_id)  # Fetch the user object

    if user is None:
        return jsonify(message="User not found"), 404

    # Generate a new access token for the user
    new_access_token = create_access_token(identity=current_user_id)

    # Return the new access token to the client
    session['access_token']=new_access_token

    return {'access_token':new_access_token}, 200 # Return a 200 OK

