from flask import Flask, url_for, render_template, redirect, session, abort, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from settings import DISCORD_OAUTH2_PROVIDER_INFO, FLASK_SECRET, ADMIN_IDS
from werkzeug.exceptions import HTTPException
from urllib.parse import urlencode, unquote
from pprint import pprint
import requests, secrets

app = Flask("__name__")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SECRET_KEY"] = FLASK_SECRET
app.config['OAUTH2_PROVIDER'] = DISCORD_OAUTH2_PROVIDER_INFO

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    money = db.Column(db.Integer, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_bracketmaster = db.Column(db.Boolean, default=False)

    # email is optional, just for updates
    avatar = db.Column(db.String(128), nullable=True)
    email = db.Column(db.String(64), nullable=True)


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route("/")
def index():
    return render_template('index.jinja')

@app.route("/bets")
@login_required
def bets():
    return render_template('bets.jinja')

@app.route("/leaderboard")
def leaderboard():
    users = db.session.execute(db.select(User).order_by(User.money)).all()
    return render_template('leaderboard.jinja', users=[user[0] for user in users[::-1]])


########################################################################################################################
# Login + User
########################################################################################################################

@app.route("/login")
def login():
    if not current_user.is_anonymous:
        return redirect(url_for('profile'))
    
    return render_template('login.jinja')


@app.route("/logout")
def logout():
   logout_user()
   return render_template('logout.jinja')


@app.route("/auth")
def authorize():
    if not current_user.is_anonymous:
        return redirect(url_for('profile'))

    session['oauth2_state'] = secrets.token_urlsafe(16)
    
    provider_data = app.config['OAUTH2_PROVIDER']

    query_string = urlencode({
        'client_id': provider_data['client_id'],
        'response_type': 'code',
        'redirect_uri': url_for('callback', _external=True),
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    return redirect(provider_data['authorize_url'] + '?' + query_string)


@app.route("/callback")
def callback():
    if not current_user.is_anonymous:
        return redirect(url_for('profile'))

    provider_data = app.config['OAUTH2_PROVIDER']
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                render_template(f'{k}: {v}')        
        return redirect(url_for('index'))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    # make sure that the authorization code is present
    if 'code' not in request.args:
        abort(401)

    # exchange the authorization code for an access token
    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('callback', _external=True),
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(provider_data['userinfo-req']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,  # a quick skim of the oauth2 spec leads me to think that my tokens are always gonna be bearer tokens
        'Accept': 'application/json',
    })
    
    if response.status_code != 200:
        abort(401)
    
    id = provider_data['userinfo-req']['id'](response.json())
    username = provider_data['userinfo-req']['username'](response.json())
    avatar_uri = provider_data['userinfo-req']['avatar_uri'](response.json())

    # find or create the user in the database
    user = db.session.scalar(db.select(User).where(User.id == id))
    if user is None:
        user = User(id=id, username=username, money=0, avatar=avatar_uri)
        db.session.add(user)
        db.session.commit()

    # # log the user in
    login_user(user)
    return redirect(url_for('profile'))


@app.route("/profile")
@login_required
def profile():
    return render_template('profile.jinja')


@app.route("/profile/update")
@login_required
def update_user():
    try:
        current_user.avatar = unquote(request.args['avatar'])
        current_user.email = request.args['email']
    except:
        flash('error: malformed query string')
        return redirect(url_for('profile'))
    
    try:
        db.session.commit()
    except:
        flash('error: failed to commit to db')
        return redirect(url_for('profile'))

    return redirect(url_for('profile'))


########################################################################################################################
# Bracketmaster
########################################################################################################################

@app.route("/bracketmaster")
@login_required
def bracketmaster():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    return render_template('bracketmaster.jinja')



########################################################################################################################
# Admin
########################################################################################################################

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return abort(403)
    return render_template('admin/admin.jinja')


@app.route("/admin/nuke-table")
@login_required
def admin_nuke_table():
    if not current_user.is_admin:
        return abort(403)
    
    table = request.args.get('table')
    if table not in db.metadata.tables:
        flash(f"bad table name. table {table} not in database")
        return redirect(url_for('admin'))

    print(type(db.metadata.tables['users']))
    db.session.execute(db.metadata.tables[table].delete())
    db.session.commit()

    if table == "users":
        logout_user()
        return redirect(url_for('index'))
    else:
        return redirect(url_for('admin'))
    

@app.route("/admin/test-endpoint")
@login_required
def admin_test():
    # thing ur testing goes here
    if not current_user.is_admin:
        return abort(403)
    return redirect(url_for("admin"))


@app.route("/admin/manage-users")
@login_required
def admin_manage_users():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    users = db.session.execute(db.select(User).order_by(User.username)).all()
    return render_template("admin/manage-users.jinja", users=users)


@app.route("/admin/manage-users/update/")
@login_required
def admin_update_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    id = int(request.args['id'])
    user = db.get_or_404(User, id)
    
    try:
        user.money = int(request.args['money'])
        user.is_admin = 'is_admin' in request.args
        user.is_bracketmaster = 'is_bracketmaster' in request.args
        user.avatar = unquote(request.args['avatar'])
        user.email = request.args['email']
    except:
        flash('error: malformed query string')
        return redirect(url_for('admin_manage_users'))
    
    try:
        db.session.commit()
    except:
        flash('error: failed to commit to db')
        return redirect(url_for('admin_manage_users'))

    return redirect(url_for('admin_manage_users'))


@app.route("/admin/manage-users/delete/")
@login_required
def admin_delete_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))

    id = int(request.args['id'])
    user = db.get_or_404(User, id)
    
    try:
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        flash('error: could not delete user')
        flash(str(e))
        return redirect(url_for('admin_manage_users'))
    
    return redirect(url_for('admin_manage_users'))


@app.route("/admin/test-user-panel-flash")
@login_required
def admin_test_user_panel_flash():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    flash('testing flash')
    return redirect(url_for('admin_manage_users'))


@app.route("/admin/test-admin-landing-flash")
@login_required
def admin_test_landing_flash():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    flash('testing flash')
    return redirect(url_for('admin'))


# error handler. tosses you to 404 page for pnf errors, a different page for everything else
@app.errorhandler(HTTPException) 
def not_found(e):
    if (e.code == 403):
        return render_template("errors/403.jinja")
    elif (e.code == 404):
        return render_template("errors/404.jinja")
    else:
        return render_template("errors/gen-error.jinja", code=e.code)


# THIS IS FOR DEV PURPOSES CAUSE IM LAZY AND DONT WANNA DO IT MANUALLY EVERY TIME
# UNDER NO CIRCUMSTANCES SHOULD THIS BE IN THE FINAL VERSION
@app.route("/give_admin")
def give_admin():
    for id in ADMIN_IDS:
        user = db.session.scalar(db.select(User).where(User.id == id))
        if user:
            user.is_admin = True
            user.is_bracketmaster = True
            db.session.commit()

    return redirect(url_for("admin"))


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, port=5678)