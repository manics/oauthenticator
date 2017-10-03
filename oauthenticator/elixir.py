"""
Custom Authenticator to use Elixir AAI OAuth with JupyterHub

Based on
- oauthenticator/generic.py
- https://github.com/neicnordic/Elixir-OAuth2-python-example
- Development Guide for ELIXIR OIDC:
  https://docs.google.com/document/d/1vOyW4dLVozy7oQvINYxHheVaLvwNsvvghbiKTLg7RbY
"""
import base64
import json
import os
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from .oauth2 import OAuthLoginHandler, OAuthenticator

ELIXIR_URL = os.environ.get('ELIXIR_URL') or 'https://perun.elixir-czech.cz'
ELIXIR_AUTHORIZE_URL = "%s/oidc/authorize" % ELIXIR_URL
ELIXIR_ACCESS_TOKEN_URL = "%s/oidc/token" % ELIXIR_URL
#ELIXIR_USER_URL = "%s/oauth/rpc/json/oidcManager/userinfo" % ELIXIR_URL


class ElixirMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = ELIXIR_AUTHORIZE_URL
    _OAUTH_ACCESS_TOKEN_URL = ELIXIR_ACCESS_TOKEN_URL


class ElixirLoginHandler(OAuthLoginHandler, ElixirMixin):
    # TODO: does this work?
    #scope = ['openid', 'profile', 'email', 'bona_fide_status']
    scope = ['profile', 'email']


def decode_jwt_details(token):
    # https://github.com/jpadilla/pyjwt/blob/1.5.3/jwt/utils.py#L33
    details = token.split('.')[1]
    rem = len(details) % 4
    if rem > 0:
        details += '=' * (4 - rem)
    j = base64.urlsafe_b64decode(details).decode('utf-8')
    return json.loads(j)


class ElixirOAuthenticator(OAuthenticator):

    login_service = "Elixir"

    login_handler = ElixirLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument('code')
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
        )

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }
        req = HTTPRequest(ELIXIR_ACCESS_TOKEN_URL,
                          method="POST",
                          headers=headers,
                          body=urllib.parse.urlencode(params)
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        token_type = resp_json['token_type']

        details = decode_jwt_details(access_token)
        return details['sub']


class LocalElixirOAuthenticator(LocalAuthenticator, ElixirOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
