from decouple import config

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
            'user': lambda json: json['username'],
        },
        'scopes': ['identify'],
}