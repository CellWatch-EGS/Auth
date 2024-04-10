# main.py

from flask import Blueprint, render_template, jsonify, session, make_response, request
from flask_login import login_required, current_user
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import requests

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('login.html')

@main.route('/profile')
@login_required
def profile():
    
    print("\n\n ta aqui o user? ", current_user.name, " e tambem ", current_user.email, "\n\n")

    access_token = request.cookies.get('access_token')

    # Send a GET request without including an access token


    # if current_user.is_authenticated:
    #     return f'Hello, {current_user.email}!'
    # else:
    #     return 'You are not logged in.'
    
    return render_template('profile.html', name=current_user.name, token=access_token)
