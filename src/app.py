from flask import Flask, url_for, render_template, redirect, session, abort, request, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.exceptions import HTTPException
from urllib.parse import urlencode, unquote
from pprint import pprint
from typing import Optional
import requests, secrets, random, base64, os, math, json

from settings import DISCORD_OAUTH2_PROVIDER_INFO, FLASK_SECRET, ADMIN_IDS
from bracket import Bracket, Competitor, Match
from draw import DrawData, Line, BracketImage

app = Flask("__name__")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config["SECRET_KEY"] = FLASK_SECRET
app.config['OAUTH2_PROVIDER'] = DISCORD_OAUTH2_PROVIDER_INFO

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login = LoginManager(app)
login.login_view = 'login'


# region DB Classes

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    money: Mapped[int]
    avatar: Mapped[str]

    is_admin: Mapped[bool] = mapped_column(default=False)
    is_bracketmaster: Mapped[bool] = mapped_column(default=False)
    
    # email is optional, just for updates
    email: Mapped[Optional[str]]


class Deck(db.Model):
    __tablename__ = 'decks'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    matches: Mapped[int]
    wins: Mapped[int]
    image_uri: Mapped[Optional[str]]


class BracketData(db.Model):
    __tablename__ = 'bracket'
    id: Mapped[int] = mapped_column(primary_key=True)
    is_active: Mapped[bool]
    bracket_json: Mapped[bytes] # yes im storing them completely seperately
    draw_json: Mapped[bytes]    # no i dont wanna talk about it

# endregion

# region Helpers

def moveEmptyToEnd(obj_list: list[tuple[BracketData]] | list[tuple[Deck]]) -> None:
    # moves decks/brackets with empty names to the end of the list. mutates, doesnt return.
    i = 0
    end = len(obj_list)
    while i < end:
        if obj_list[i][0].name == "":
            obj_list.append(obj_list.pop(i))
            end -= 1
        else:
            i += 1


def databaseEntryToJson(bracket_data: BracketData) -> Bracket:
    return base64.b64decode(bracket_data.bracket_json).decode('utf-8')

def databaseEntryToDrawJson(bracket_data: BracketData) -> Bracket:
    return base64.b64decode(bracket_data.draw_json).decode('utf-8')

def bracketObjectToBytes(bracket_object: Bracket) -> bytes:
    return base64.b64encode(bracket_object.to_json().encode('utf-8'))

def drawObjectToBytes(draw_object: DrawData) -> bytes:
    return base64.b64encode(draw_object.to_json().encode('utf-8'))

def getBracketNameFromDBEntry(bracket_data: BracketData) -> str:
    return json.loads(base64.b64decode(bracket_data.bracket_json).decode('utf-8'))['name']


def createEmptyMatchTreeWithGivenDepth(depth: int) -> Bracket:
    root = Match()
    if depth == 0:
        return root
    root.left = createEmptyMatchTreeWithGivenDepth(depth - 1)
    root.right = createEmptyMatchTreeWithGivenDepth(depth - 1)
    return root

# endregion

# region Bracket

@app.route("/")
def index():
    # current display is 480x256 units (1 unit = .125rem = 2px w/ default rem size) [it accepts floats so if you wanna get pixel precise .5s'll getcha there]

    bracket_data = db.session.execute(db.select(BracketData).filter_by(is_active=True)).one()[0]
    draw = DrawData(databaseEntryToDrawJson(bracket_data))
    print(draw)
    bracket = Bracket(databaseEntryToJson(bracket_data))
    matches = bracket.top.generate_match_list()
    decks_data = db.session.execute(db.select(Deck).order_by(Deck.name)).all()
    decks = {deck[0].id: deck[0].image_uri for deck in decks_data}

    
    # draw.image_size = (60, 60)
    # draw.add_lines([Line(157.5, 64, 128, True), Line(147.5, 64, 10, False), Line(147.5, 192, 10, False), Line(160, 128, 10, False), # left semis
    #                 Line(322.5, 64, 132, True), Line(325, 64, 10, False), Line(325, 195, 10, False), Line(312.5, 128, 10, False), # right semis
    #                 Line(232.5, 128, 17.5, False), Line(240, 72.5, 55.5, True), # final
    #                 Line(72.5, 30, 65.33, True), Line(62.5, 30, 10, False), Line(62.5, 95.33, 10, False), Line(75, 64, 10, False), # lt quarters
    #                 Line(72.5, 161.66, 65.33, True), Line(62.5, 161.66, 10, False), Line(62.5, 226, 10, False), Line(75, 192, 10, False), # lb quarters
    #                 Line(407.5, 30, 65.33, True), Line(410, 30, 10, False), Line(410, 95.33, 10, False), Line(397.5, 64, 10, False), # rt quarters
    #                 Line(407.5, 161.66, 65.33, True), Line(410, 161.66, 10, False), Line(410, 226, 10, False), Line(397.5, 192, 10, False)]) # rb quarters
    # draw.images += [BracketImage(210,10), BracketImage(170,98), BracketImage(85,34), BracketImage(0,0), BracketImage(0,65.33), BracketImage(85,162), 
    #                 BracketImage(0,131.66), BracketImage(0,196), BracketImage(250,98), BracketImage(335,36), BracketImage(420,0), BracketImage(420,65.33), \
    #                 BracketImage(335,166), BracketImage(420,131.66), BracketImage(420,196)]


    if (len(matches) != len(draw.images)):
        raise ValueError("draw data and match data are of different lengths")

    return render_template('index.jinja', matches=matches, draw_data=draw, decks=decks)


# https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTqW56asf72CeWy1YpaecZIJxcfMUJ3vyN2Rg&s


# build out an editor for making brackets (or at least a code editor with live preview and qol features)

# endregion

# region Major Pages

@app.route("/bets")
@login_required
def bets():
    return render_template('bets.jinja')

@app.route("/leaderboard")
def leaderboard():
    users = db.session.execute(db.select(User).order_by(User.money)).all()
    return render_template('leaderboard.jinja', users=[user[0] for user in users[::-1]])

@app.errorhandler(HTTPException) 
def not_found(e):
    if (e.code == 403):
        return render_template("errors/403.jinja")
    elif (e.code == 404):
        return render_template("errors/404.jinja")
    else:
        return render_template("errors/gen-error.jinja", code=e.code)

# endregion

# region Login + User

@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route("/login")
def login():
    if not current_user.is_anonymous:
        return redirect(url_for('profile'))
    
    return render_template('user/login.jinja')


@app.route("/logout")
def logout():
   logout_user()
   return render_template('user/logout.jinja')


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
        login_user(user)
        return redirect(url_for('profile'))

    # # log the user in
    login_user(user)
    return redirect(url_for('index'))


@app.route("/profile")
@login_required
def profile():
    return render_template('user/profile.jinja')


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

# endregion 

# region Bracketmaster

@app.route("/bracketmaster")
@login_required
def bracketmaster():
    if not current_user.is_bracketmaster:
        return abort(403)
    return render_template('bracketmaster/bracketmaster.jinja')


@app.route("/bracketmaster/manage-decks")
@login_required
def bracketmaster_manage_decks():
    if not current_user.is_bracketmaster:
        return abort(403)
    decks = db.session.execute(db.select(Deck).order_by(Deck.name)).all()
    moveEmptyToEnd(decks)
    return render_template('bracketmaster/manage-decks.jinja', decks=decks)


@app.route("/bracketmaster/manage-decks/update_deck")
@login_required
def bracketmaster_update_deck():
    if not current_user.is_bracketmaster:
        return abort(403)
    
    id = int(request.args['id'])
    deck = db.get_or_404(Deck, id)

    try:
        deck.name = unquote(request.args['name'])
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
        return abort(403)
    
    found_valid_id = False
    while not found_valid_id:
        try:
            id = random.randint(0, 4294967295)
            db.get_or_404(Deck, id)
            
        except:
            found_valid_id = True

    deck = Deck(id=id, name="", matches=0, wins=0, image_uri="")
    db.session.add(deck)
    db.session.commit()

    return redirect(url_for('bracketmaster_manage_decks'))
    

@app.route("/bracketmaster/manage-decks/delete_deck")
@login_required
def bracketmaster_delete_deck():
    if not current_user.is_bracketmaster:
        return abort(403)
    
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
        return abort(403)
    
    brackets = db.session.execute(db.select(BracketData)).all()
    names = [getBracketNameFromDBEntry(bracket[0]) for bracket in brackets]

    return render_template('bracketmaster/manage-brackets.jinja', brackets=brackets, names=names)


@app.route("/bracketmaster/create-bracket")
@login_required
def bracketmaster_create_bracket():
    if not current_user.is_bracketmaster:
        return abort(403)
    
    return render_template('bracketmaster/build/template-options.jinja')


@app.route("/bracketmaster/delete-bracket")
@login_required
def bracketmaster_delete_bracket():
    if not current_user.is_bracketmaster:
        return abort(403)
    
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
        return abort(403)

    id = int(request.args['id'])
    bracket = db.get_or_404(BracketData, id)

    try:
        bracket_obj = Bracket(databaseEntryToJson(bracket))
        bracket_obj.name = unquote(request.args['name'])
        bracket.bracket_json = bracketObjectToBytes(bracket_obj)

        bracket.is_active = 'is_active' in request.args        
        db.session.commit()
    except Exception as e:
        flash('there was an error updating bracket name')
        flash(str(e))
        return redirect(url_for('bracketmaster_manage_brackets'))
    
    return redirect(url_for('bracketmaster_manage_brackets'))


@app.route("/bracketmaster/manage-bracket/<int:id>")
@login_required
def bracketmaster_edit_bracket(id):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket = db.get_or_404(BracketData, id)

    return render_template('bracketmaster/manage-bracket.jinja', id=id, name=getBracketNameFromDBEntry(bracket))


@app.route("/bracketmaster/manage_bracket/<int:id>/active_matches")
@login_required
def bracketmaster_manage_active_matches(id):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket_data = db.get_or_404(BracketData, id)
    bracket = Bracket(databaseEntryToJson(bracket_data))

    matches = [match for match in bracket.top.generate_match_list() if match.is_ready()]
    
    return render_template("bracketmaster/manage-active-matches.jinja", matches=matches, id=id)


@app.route("/bracketmaster/manage_bracket/<int:id>/active_matches/declare_winner/<int:index>/<string:competitor>")
@login_required
def bracketmaster_declare_winner(id, index, competitor):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket_data = db.get_or_404(BracketData, id)
    bracket = Bracket(databaseEntryToJson(bracket_data))

    matches = [match for match in bracket.top.generate_match_list() if match.is_ready()]
    bracket.top.override_same_match(matches[index], matches[index].declare_winner(competitor == "left"))

    bracket_data.bracket_json = bracketObjectToBytes(bracket)
    db.session.commit()

    return redirect(url_for("bracketmaster_manage_active_matches", id=id))


@app.route("/bracketmaster/manage_bracket/<int:id>/competitors")
@login_required
def bracketmaster_edit_competitors(id):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket_data = db.get_or_404(BracketData, id)
    bracket = Bracket(databaseEntryToJson(bracket_data))

    competitors = bracket.top.generate_competitor_list()

    users = db.session.execute(db.select(User).order_by(User.username)).all()
    decks = db.session.execute(db.select(Deck).order_by(Deck.name)).all()
    
    return render_template("bracketmaster/edit-competitors.jinja", competitors=competitors, owners=users, decks=decks, id=id)


@app.route("/bracketmaster/manage_bracket/<int:id>/competitors/update")
@login_required
def bracketmaster_update_competitors(id):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket_data = db.get_or_404(BracketData, id)
    bracket = Bracket(databaseEntryToJson(bracket_data))

    competitors = []
    for i in range(len(bracket.top.generate_competitor_list())):
        competitor = Competitor()
        competitor.name = request.args[f"{i}-name"] 
        competitor.owner_id = request.args[f"{i}-owner"] 
        competitor.deck_id = request.args[f"{i}-deck"]
        competitors += [competitor]

    bracket.top.update_competitors(competitors)
    bracket_data.bracket_json = bracketObjectToBytes(bracket)
    db.session.commit()

    return redirect(url_for("bracketmaster_edit_competitors", id=id))

# not a now feature
# https://anseki.github.io/leader-line/
# https://anseki.github.io/plain-draggable/
# @app.route("/bracketmaster/manage_bracket/<int:id>/build")
# @login_required
# def bracketmaster_build_bracket(id):
#     if not current_user.is_bracketmaster:
#         return abort(403)
#     pass


@app.route("/bracketmaster/manage_bracket/<int:id>/edit_json", methods=['GET', 'POST'])
@login_required
def bracketmaster_edit_json_data(id):
    if not current_user.is_bracketmaster:
        return abort(403)
    
    bracket = db.get_or_404(BracketData, id)

    if request.method == 'GET':
        json = json.dumps(json.loads(databaseEntryToJson(bracket)), indent=4)
        return render_template('bracketmaster/edit-json-data.jinja', id=id, name=getBracketNameFromDBEntry(bracket), json=json)
    elif request.method == 'POST':
        try:
            encoded_json = json.loads(unquote(request.data))["base64"]
            decoded_json = base64.b64decode(encoded_json.encode("utf-8")).decode('utf-8')
            minified_json = json.dumps(json.loads(decoded_json))
            print(minified_json)
        except:
            return "json decode error"
        
        try:
            bracket.bracket_json = bracketObjectToBytes(Bracket(minified_json))
            db.session.commit()
        except:
            return "error pushing to db"

        return "success! :D"
    

@app.route("/bracketmaster/create-bracket/single-elimination")
@login_required
def bracketmaster_build_single_elim():
    if not current_user.is_bracketmaster:
        return abort(403)
    
    if "size" not in request.args:
        return render_template("bracketmaster/build/single-elimination-landing.jinja")

    size = int(request.args["size"])

    if "bracket-name" not in request.args:
        users = db.session.execute(db.select(User).order_by(User.username)).all()
        decks = db.session.execute(db.select(Deck).order_by(Deck.name)).all()
        return render_template("bracketmaster/build/single-elimination.jinja", size=size, owners=users, decks=decks)

    try:
        depth = int(math.ceil(math.log2(size)))
        top = createEmptyMatchTreeWithGivenDepth(depth)

        for i in range(size):
            competitor = Competitor()
            competitor.name = request.args[f"{i}-name"] 
            competitor.owner_id = request.args[f"{i}-owner"] 
            competitor.deck_id = request.args[f"{i}-deck"]
        
            # determining bracket pos. based on seed. using 2**depth to allow for non-power-of-two sizes
            if i < (2**depth) // 2:
                bracket_pos = i*2
            else:
                bracket_pos = ((2**depth) - i - 1) * 2 + 1

            bin_string = "{0:b}".format(bracket_pos).zfill(depth)

            match = top
            while bin_string != "":
                if bin_string[0] == "0":
                    match = match.left
                else:
                    match = match.right
                bin_string = bin_string[1:]
            match.competitor = competitor

        b = Bracket()
        b.name = request.args["bracket-name"]
        b.top = top
    except Exception as e:
        flash('something went wrong when building the bracket object')
        flash(str(e))
        return redirect(url_for("bracketmaster_manage_brackets"))
    
    try:
        found_valid_id = False
        while not found_valid_id:
            try:
                id = random.randint(0, 4294967295)
                db.get_or_404(BracketData, id)
                
            except:
                found_valid_id = True

        bracket = BracketData(id=id, is_active=False, bracket_json=bracketObjectToBytes(b), draw_json=drawObjectToBytes(DrawData()))
        db.session.add(bracket)
        db.session.commit()
    except Exception as e:
        flash('something went wrong when pushing your bracket object to the database')
        flash(str(e))
        return redirect(url_for("bracketmaster_manage_brackets"))
        
    return redirect(url_for("bracketmaster_manage_brackets"))


@app.route("/bracketmaster/create-bracket/empty")
@login_required
def bracketmaster_build_empty():
    if not current_user.is_bracketmaster:
        return abort(403)
    
    try:
        found_valid_id = False
        while not found_valid_id:
            try:
                id = random.randint(0, 4294967295)
                db.get_or_404(BracketData, id)
                
            except:
                found_valid_id = True

        b = Bracket()
        b.name = "Empty Bracket"

        bracket = BracketData(id=id, is_active=False, bracket_json=bracketObjectToBytes(b), draw_json=drawObjectToBytes(DrawData()))
        db.session.add(bracket)
        db.session.commit()
    except Exception as e:
        flash('something went wrong when pushing your bracket object to the database')
        flash(str(e))
        return redirect(url_for("bracketmaster_manage_brackets"))
        
    return redirect(url_for("bracketmaster_manage_brackets"))


# endregion

# region Admin

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

    db.session.execute(db.metadata.tables[table].delete())
    db.session.commit()

    if table == "users":
        logout_user()
        return redirect(url_for('index'))
    else:
        return redirect(url_for('admin'))
    

@app.route("/admin/nuke-all-tables")
@login_required
def admin_nuke_all_tables():
    if not current_user.is_admin:
        return abort(403)
    
    db.drop_all()
    db.create_all()
    db.session.commit()

    return redirect(url_for('index'))


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
        return abort(403)
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


@app.route("/admin/build-test-db")
@login_required
def admin_build_test_db():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    
    db.drop_all()
    db.create_all()

    # users
    scott = User(id=335575787509907456, username='justcookiedough', money=125, avatar="https://cdn.discordapp.com/avatars/335575787509907456/91bc0a112ec59a4f16e621f12746706f.png", email='scottangelides@gmail.com', is_admin=True, is_bracketmaster=True)
    scott_alt = User(id=971243193750401044, username='cookiedonut7182', money=42, avatar="https://cdn.discordapp.com/avatars/971243193750401044/d5d54dd355c84baeb4b5b8d06d522f99.png")
    db.session.add(scott)
    db.session.add(scott_alt)

    # decks
    smeargle = Deck(id=1234, name="Smeargle", matches=0, wins=0, image_uri="https://tiermaker.com/images/media/template_images/2024/17264189/pokmon-tcg-tournament-17264189/012d0047-fed7-4ea7-a42a-1f2f6f80b7f9.png")
    steven = Deck(id=42, name="Steven", matches=100, wins=100, image_uri="https://tiermaker.com/images/media/template_images/2024/17264189/pokmon-tcg-tournament-17264189/b47423a2-65f4-48b7-8c7c-a4ac706ae390.png")
    db.session.add(smeargle)
    db.session.add(steven)

    # bracket
    bracket = BracketData(id=8765309, 
                          is_active=True, 
                          bracket_json=bracketObjectToBytes(Bracket('{"name": "Test Bracket", "matches": [{"competitor": -1, "left": 1, "right": 8}, {"competitor": -1, "left": 2, "right": 5}, {"competitor": -1, "left": 3, "right": 4}, {"competitor": {"name": "Cookie A", "owner_id": "335575787509907456", "deck_id": "42"}, "left": -1, "right": -1}, {"competitor": {"name": "Donut D", "owner_id": "971243193750401044", "deck_id": "1234"}, "left": -1, "right": -1}, {"competitor": -1, "left": 6, "right": 7}, {"competitor": {"name": "Donut A", "owner_id": "971243193750401044", "deck_id": "1234"}, "left": -1, "right": -1}, {"competitor": {"name": "Cookie D", "owner_id": "335575787509907456", "deck_id": "42"}, "left": -1, "right": -1}, {"competitor": -1, "left": 9, "right": 12}, {"competitor": -1, "left": 10, "right": 11}, {"competitor": {"name": "Cookie B", "owner_id": "335575787509907456", "deck_id": "42"}, "left": -1, "right": -1}, {"competitor": {"name": "Donut C", "owner_id": "971243193750401044", "deck_id": "1234"}, "left": -1, "right": -1}, {"competitor": -1, "left": 13, "right": 14}, {"competitor": {"name": "Donut B", "owner_id": "971243193750401044", "deck_id": "1234"}, "left": -1, "right": -1}, {"competitor": {"name": "Cookie C", "owner_id": "335575787509907456", "deck_id": "42"}, "left": -1, "right": -1}]}')),
                          draw_json=drawObjectToBytes(DrawData('{"image_size": [60, 60], "images": [{"x": 210, "y": 10}, {"x": 170, "y": 98}, {"x": 85, "y": 34}, {"x": 0, "y": 0}, {"x": 0, "y": 65.33}, {"x": 85, "y": 162}, {"x": 0, "y": 131.66}, {"x": 0, "y": 196}, {"x": 250, "y": 98}, {"x": 335, "y": 36}, {"x": 420, "y": 0}, {"x": 420, "y": 65.33}, {"x": 335, "y": 166}, {"x": 420, "y": 131.66}, {"x": 420, "y": 196}], "lines": [{"isVert": true, "size": 128, "x": 157.5, "y": 64}, {"isVert": false, "size": 10, "x": 147.5, "y": 64}, {"isVert": false, "size": 10, "x": 147.5, "y": 192}, {"isVert": false, "size": 10, "x": 160, "y": 128}, {"isVert": true, "size": 132, "x": 322.5, "y": 64}, {"isVert": false, "size": 10, "x": 325, "y": 64}, {"isVert": false, "size": 10, "x": 325, "y": 195}, {"isVert": false, "size": 10, "x": 312.5, "y": 128}, {"isVert": false, "size": 17.5, "x": 232.5, "y": 128}, {"isVert": true, "size": 55.5, "x": 240, "y": 72.5}, {"isVert": true, "size": 65.33, "x": 72.5, "y": 30}, {"isVert": false, "size": 10, "x": 62.5, "y": 30}, {"isVert": false, "size": 10, "x": 62.5, "y": 95.33}, {"isVert": false, "size": 10, "x": 75, "y": 64}, {"isVert": true, "size": 65.33, "x": 72.5, "y": 161.66}, {"isVert": false, "size": 10, "x": 62.5, "y": 161.66}, {"isVert": false, "size": 10, "x": 62.5, "y": 226}, {"isVert": false, "size": 10, "x": 75, "y": 192}, {"isVert": true, "size": 65.33, "x": 407.5, "y": 30}, {"isVert": false, "size": 10, "x": 410, "y": 30}, {"isVert": false, "size": 10, "x": 410, "y": 95.33}, {"isVert": false, "size": 10, "x": 397.5, "y": 64}, {"isVert": true, "size": 65.33, "x": 407.5, "y": 161.66}, {"isVert": false, "size": 10, "x": 410, "y": 161.66}, {"isVert": false, "size": 10, "x": 410, "y": 226}, {"isVert": false, "size": 10, "x": 397.5, "y": 192}]}')))
    db.session.add(bracket)

    db.session.commit()

    flash('done!')
    return redirect(url_for('admin'))


# endregion

# region Dev

@app.route("/give_admin")
def give_admin():
    for id in ADMIN_IDS:
        user = db.session.scalar(db.select(User).where(User.id == id))
        if user:
            user.is_admin = True
            user.is_bracketmaster = True
            db.session.commit()

    return redirect(url_for("admin"))

# endregion


with app.app_context():
    db.create_all()

if __name__ == "__main__":

    # ensure correct working directory
    cwd_list = os.getcwd().split("/")
    if not (cwd_list[-2] == "pokemania" and cwd_list[-1] == "src"):
        print("file is not running from ./src - changing cwd")
        os.chdir("/".join(__file__.split("/")[:-1]))
        print(f"new cwd is {os.getcwd()}")

    app.run(debug=True, port=5678)