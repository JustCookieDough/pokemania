from decouple import config

FLASK_SECRET = config('FLASK_SECRET')

OAUTH_ID = config('DISCORD_CLIENT_ID')
OAUTH_SECRET = config('DISCORD_CLIENT_SECRET')

OAUTH_AUTH_URL = "https://discord.com/oauth2/authorize"
OAUTH_TOKEN_URL = "https://discord.com/api/oauth2/token"

DISCORD_OAUTH2_PROVIDER_INFO = {
        'client_id': OAUTH_ID,
        'client_secret': OAUTH_SECRET,
        'authorize_url': OAUTH_AUTH_URL,
        'token_url': OAUTH_TOKEN_URL,
        'userinfo-req': {
            'url': 'https://discord.com/api/users/@me',
            'username': lambda json: json['username'],
            'id': lambda json: json['id'],
            'avatar_uri': lambda json: "https://cdn.discordapp.com/avatars/"+json['id']+"/"+json['avatar']+".png"
        },
        'scopes': ['identify'],
}

# FOR DEBUGGING PURPOSES ONLY, REMOVE THIS FOR PROD
ADMIN_IDS = [335575787509907456, 399697395564281866]