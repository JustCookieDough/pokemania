from flask import Flask
from flask import url_for, render_template
from settings import DISCORD_OAUTH2_PROVIDER_INFO
from werkzeug.exceptions import HTTPException

app =Flask("__name__")

app.config['OAUTH2_PROVIDER'] = DISCORD_OAUTH2_PROVIDER_INFO

@app.route("/")
def index():
    return render_template('index.jinja')


@app.route("/login")
def login():
    return render_template('login.jinja')


@app.route("/auth")
def authorize():
   pass

@app.route("/callback")
def oauth2_callback():
   pass

@app.route("/bets")
def bets():
    return render_template('bets.jinja')


@app.route("/leaderboard")
def leaderboard():
    return render_template('leaderboard.jinja')


# error handler. tosses you to 404 page for pnf errors, a different page for everything else
@app.errorhandler(HTTPException) 
def not_found(e):
  if (e.code == 404):
    return render_template("404.jinja")
  else:
     return render_template("error.jinja", code=e.code)



if __name__ == "__main__":
    app.run(debug=True, port=5678)