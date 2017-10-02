"""
Custom Authenticator to use Elixir AAI OAuth with JupyterHub

Based on
- oauthenticator/openshift.py
- https://github.com/neicnordic/Elixir-OAuth2-python-example
- Development Guide for ELIXIR OIDC:
  https://docs.google.com/document/d/1vOyW4dLVozy7oQvINYxHheVaLvwNsvvghbiKTLg7RbY
"""
from base64 import urlsafe_b64decode
import json
import os

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


# https://github.com/jpadilla/pyjwt/blob/72bb76cb343bb6d0f40fcd0d136898b8ba08c323/jwt/utils.py#L33
def decode_jwt_details(access_token):
    access_token = access_token.encode('ascii').split('.')[1]
    rem = len(access_token) % 4
    if rem > 0:
        access_token += b'=' * (4 - rem)
    j = urlsafe_b64decode(access_token)
    return json.loads(j)


class ElixirOAuthenticator(OAuthenticator):

    login_service = "Elixir"

    login_handler = ElixirLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        http_client = AsyncHTTPClient()

        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="authorization_code",
            code=code
        )

        url = url_concat(ELIXIR_ACCESS_TOKEN_URL, params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        details = decode_jwt_details(access_token)
        return details['sub']


class LocalElixirOAuthenticator(LocalAuthenticator, ElixirOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
