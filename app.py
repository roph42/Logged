import os
import secrets
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import Flask, redirect, url_for, render_template, flash, session, \
    current_app, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user,\
    current_user
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'top secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['OAUTH2_PROVIDERS'] = {
    'google': {
        'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
        'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
        'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
        'token_url': 'https://accounts.google.com/o/oauth2/token',
        'userinfo': {
            'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
            'email': lambda json: json['email'],
        },
        'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
    },
    'github': {
        'client_id': os.environ.get('GITHUB_CLIENT_ID'),
        'client_secret': os.environ.get('GITHUB_CLIENT_SECRET'),
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'userinfo': {
            'url': 'https://api.github.com/user/emails',
            'email': lambda json: json[0]['email'],
        },
        'scopes': ['user:email'],
    },
    'facebook': {
        'client_id': os.environ.get('FACEBOOK_CLIENT_ID'),
        'client_secret': os.environ.get('FACEBOOK_CLIENT_SECRET'),
        'authorize_url': '',
        'token_url': '',
        'userinfo': {
            'url': '',
            'email': '',
        },
        'scopes': [''],
    },
    'linkedin': {
        'client_id': os.environ.get('LINKEDIN_CLIENT_ID'),
        'client_secret': os.environ.get('LINKEDIN_CLIENT_SECRET'),
        'authorize_url': 'https://www.linkedin.com/oauth/v2/authorization',
        'token_url': 'https://www.linkedin.com/oauth/v2/accessToken',
        'userinfo': {
            'url': 'https://api.linkedin.com/v2/userinfo',
            'email': lambda json: json['email'],
        },
        'scopes': ['email'],
    },
    'microsoft': {
        'client_id': os.environ.get('MICROSOFT_CLIENT_ID'),
        'client_secret': os.environ.get('MICROSOFT_CLIENT_SECRET'),
        'authorize_url': '',
        'token_url': '',
        'userinfo': {
            'url': '',
            'email': '',
        },
        'scopes': [''],
    },
}

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'index'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    provider = db.Column(db.String(20), nullable=False, default='app')

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/authorize/<provider>')
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    session['oauth2_state'] = secrets.token_urlsafe(16)

    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    return redirect(provider_data['authorize_url'] + '?' + qs)


@app.route('/callback/<provider>')
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                flash(f'{k}: {v}')
        return redirect(url_for('index'))

    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    if 'code' not in request.args:
        abort(401)

    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    if response.status_code != 200:
        abort(401)
    print(provider_data['userinfo'])
    email = provider_data['userinfo']['email'](response.json())

    user = db.session.scalar(db.select(User).where(User.email == email))
    if user is None:
        user = User(email=email, username=email.split('@')[0], provider=provider)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('index'))

# @app.route('/')
# def show_users():
#     users = User.query.all()
#     return render_template('index.html', users=users)


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
