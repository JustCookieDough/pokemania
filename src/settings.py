from decouple import config

OAUTH_ID = config('DISCORD_CLIENT_ID')
OAUTH_SECRET = config('DISCORD_CLIENT_SECRET')

OAUTH_AUTH_URL = "https://discord.com/oauth2/authorize"
OAUTH_TOKEN_URL = "https://discord.com/api/oauth2/token"
OAUTH_TOKEN_REVOKE_URL = "https://discord.com/api/oauth2/token/revoke"