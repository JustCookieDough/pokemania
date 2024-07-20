from flask import Flask, url_for, render_template, redirect, session, abort, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.exceptions import HTTPException
from urllib.parse import urlencode, unquote
from pprint import pprint
from typing import Optional
import requests, secrets, random, base64

from settings import DISCORD_OAUTH2_PROVIDER_INFO, FLASK_SECRET, ADMIN_IDS
from bracket import Bracket

app = Flask("__name__")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SECRET_KEY"] = FLASK_SECRET
app.config['OAUTH2_PROVIDER'] = DISCORD_OAUTH2_PROVIDER_INFO

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login = LoginManager(app)
login.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    money: Mapped[int]
    avatar: Mapped[str]

    is_admin: Mapped[bool] = mapped_column(default=True)
    is_bracketmaster: Mapped[bool] = mapped_column(default=True)
    
    # email is optional, just for updates
    email: Mapped[Optional[str]]


class Deck(db.Model):
    __tablename__ = 'decks'
    id: Mapped[int] = mapped_column(primary_key=True)
    deck_name: Mapped[str]
    matches: Mapped[int]
    wins: Mapped[int]
    image_uri: Mapped[Optional[str]]


class BracketData(db.Model):
    __tablename__ = 'bracket'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    bracket_data: Mapped[str]


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
    return render_template('bracketmaster/bracketmaster.jinja')


@app.route("/bracketmaster/manage-decks")
@login_required
def bracketmaster_manage_decks():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    decks = db.session.execute(db.select(Deck).order_by(Deck.deck_name)).all()
    return render_template('bracketmaster/manage-decks.jinja', decks=decks)


@app.route("/bracketmaster/manage-decks/update_deck")
@login_required
def bracketmaster_update_deck():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    id = int(request.args['id'])
    deck = db.get_or_404(Deck, id)

    try:
        deck.deck_name = unquote(request.args['deck_name'])
        deck.matches = int(request.args['matches'])
        deck.wins = int(request.args['wins'])
        deck.image_uri = unquote(request.args['image_uri'])
    except Exception as e:
        flash('error: malformed query string')
        flash(str(e))
        return redirect(url_for('bracketmaster_manage_decks'))
    
    try:
        db.session.commit()
    except:
        flash('error: failed to commit to db')
        return redirect(url_for('bracketmaster_manage_decks'))

    return redirect(url_for('bracketmaster_manage_decks'))


@app.route("/bracketmaster/manage-decks/create_deck")
@login_required
def bracketmaster_create_deck():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    found_valid_id = False
    while not found_valid_id:
        try:
            id = random.randint(0, 4294967295)
            db.get_or_404(Deck, id)
            
        except:
            found_valid_id = True

    deck = Deck(id=id, deck_name="", matches=0, wins=0, image_uri="")
    db.session.add(deck)
    db.session.commit()

    return redirect(url_for('bracketmaster_manage_decks'))
    

@app.route("/bracketmaster/manage-decks/delete_deck")
@login_required
def bracketmaster_delete_deck():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    id = int(request.args['id'])
    deck = db.get_or_404(Deck, id)
    
    try:
        db.session.delete(deck)
        db.session.commit()
    except Exception as e:
        flash('error: could not delete deck')
        flash(str(e))
        return redirect(url_for('bracketmaster_manage_decks'))
            
    return redirect(url_for('bracketmaster_manage_decks'))   

@app.route("/bracketmaster/manage-brackets")
@login_required
def bracketmaster_manage_brackets():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    brackets = db.session.execute(db.select(BracketData).order_by(BracketData.name)).all()
    return render_template('bracketmaster/manage-brackets.jinja', brackets=brackets)


@app.route("/bracketmaster/create-bracket")
@login_required
def bracketmaster_create_bracket():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    found_valid_id = False
    while not found_valid_id:
        try:
            id = random.randint(0, 4294967295)
            db.get_or_404(BracketData, id)
            
        except:
            found_valid_id = True

    b = Bracket()
    b_data = base64.b64encode(b.to_json().encode('utf-8')).decode('utf-8')

    bracket = BracketData(id=id, name="", bracket_data=b_data)
    db.session.add(bracket)
    db.session.commit()

    return redirect(url_for('bracketmaster_manage_brackets'))


@app.route("/bracketmaster/delete-bracket")
@login_required
def bracketmaster_delete_bracket():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    id = int(request.args['id'])
    bracket = db.get_or_404(BracketData, id)
    
    try:
        db.session.delete(bracket)
        db.session.commit()
    except Exception as e:
        flash('error: could not delete bracket')
        flash(str(e))
        return redirect(url_for('bracketmaster_manage_brackets'))
            
    return redirect(url_for('bracketmaster_manage_brackets')) 


@app.route("/bracketmaster/update-bracket")
@login_required
def bracketmaster_update_bracket():
    if not current_user.is_bracketmaster:
        return redirect(url_for('index'))
    
    flash("shit's busted.")
    flash("it doesn't like names with spaces in them for whatever reason")
    flash("couldn't tell you why lol")
    flash("-scott")
    return redirect(url_for('bracketmaster_manage_brackets'))

    id = int(request.args['id'])
    bracket = db.get_or_404(BracketData, id)

    try:
        print(request.args['name'], unquote(request.args['name']))
        bracket.name = unquote(request.args['name'])
        print(bracket.name)
        db.session.commit()
    except Exception as e:
        flash('there was an error updating bracket name')
        flash(str(e))
        return redirect(url_for('bracketmaster_manage_brackets'))
    
    return redirect(url_for('bracketmaster_manage_brackets'))


@app.route("/bracketmaster/manage-brackets/<int:id>")
@login_required
def bracketmaster_edit_bracket(id):
    flash('not implemented yet, sorry')
    return redirect(url_for('bracketmaster_manage_brackets'))



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