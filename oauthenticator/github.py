"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os
import re

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set, Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com/user'
else:
    GITHUB_API = '%s/api/v3/user' % GITHUB_HOST

class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST


class GitHubLoginHandler(OAuthLoginHandler, GitHubMixin):
    pass


class GitHubOAuthenticator(OAuthenticator):
    
    login_service = "GitHub"
    
    # deprecated names
    github_client_id = Unicode(config=True, help="DEPRECATED")
    def _github_client_id_changed(self, name, old, new):
        self.log.warn("github_client_id is deprecated, use client_id")
        self.client_id = new
    github_client_secret = Unicode(config=True, help="DEPRECATED")
    def _github_client_secret_changed(self, name, old, new):
        self.log.warn("github_client_secret is deprecated, use client_secret")
        self.client_secret = new
    
    client_id_env = 'GITHUB_CLIENT_ID'
    client_secret_env = 'GITHUB_CLIENT_SECRET'
    login_handler = GitHubLoginHandler
    
    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/
        
        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.get_client_id(handler),
            client_secret=self.get_client_secret(handler),
            code=code
        )
        
        url = url_concat("https://%s/login/oauth/access_token" % GITHUB_HOST,
                         params)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        
        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "token {}".format(access_token)
        }
        req = HTTPRequest("https://%s" % GITHUB_API,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["login"]


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):

    """A version that mixes in local system user creation"""
    pass


class GitHubOrgOAuthenticator(GitHubOAuthenticator):

    """A version that checks for organisation membership, and falls back
       to a user whitelist
    """

    github_organization_whitelist = Set(
        help="""
        Whitelist all users from this single GitHub organisations.

        A user must be in the whitelisted organisation or the username
        whitelist.

        TODO: This only supports a single organisation, but is defined as a
        Set to make it easier to switch to
        https://github.com/jupyterhub/oauthenticator/pull/58
        when it's ready
        """
    ).tag(config=True)

    github_organisation_etag = ''

    @gen.coroutine
    def check_whitelist(self, username):
        # No whitelist means any name is allowed, disable this:
        # https://github.com/jupyterhub/jupyterhub/blob/0.7.2/jupyterhub/auth.py#L148
        found = bool(self.whitelist) and super().check_whitelist(username)
        self.log.debug("Found user '%s'? %s", username, found)
        if not found and self.github_organization_whitelist:
            (org_users, etag) = yield self._get_github_org_members_async(
                list(self.github_organization_whitelist)[0],
                self.github_organisation_etag)
            if org_users is not None:
                self.log.info(
                    "Adding users to whitelist from organisation: %s",
                    org_users)
                self.whitelist.update(org_users)
                self.github_organisation_etag = etag
            found = bool(self.whitelist) and super().check_whitelist(username)
            self.log.debug("Found user '%s'? %s", username, found)
        return found

    @gen.coroutine
    def _get_github_org_members_async(self, github_org, etag):
        """
        Get the list of github usernames that are members of an organisation

        :param github_org: The Github organisation
        :param etag: An optional etag from a previous request.
                     This should minimise the number of API requests.
                     https://developer.github.com/v3/#conditional-requests

        :return: A tuple (list of usernames, current-etag) if `etag` was empty
                 or the list of users has changed since the provided `etag`.
                 `(None, None)` if the information has not changed since `etag`.
                 Usernames are lower-cased.
        """
        http_client = AsyncHTTPClient()
        # We don't have a handler object in this method so this will return
        # the default client_* which is fine because they should all be for
        # the same owner
        params = dict(
            client_id=self.get_client_id(),
            client_secret=self.get_client_secret(),
        )
        github_org_url = 'https://api.github.com/orgs/%s/members'
        fetch_url = url_concat(github_org_url % github_org, params)

        org_users = []

        # Check etag for the first page only
        headers = {
            "Accept": "application/json",
            "User-Agent": "oauthenticator/GitHubOrgOAuthenticator",
        }
        if etag:
            headers['If-None-Match'] = etag
        req = HTTPRequest(fetch_url, headers=headers)

        try:
            self.log.debug("HTTP request %s %s", req.url, list(req.headers.items()))
            r = yield http_client.fetch(req)
        except HTTPError as e:
            # 304: Not modified
            if e.code == 304:
                return (None, None)
            raise

        etag = r.headers.get('etag', '')

        while r:
            self.log.debug("HTTP response %s %s %s %s", r.request.url, r.code,
                           list(r.headers.items()), r.body)
            fetch_url = ''
            users = json.loads(r.body.decode('utf8', 'replace'))

            # We could use normalize_username
            # https://github.com/jupyterhub/jupyterhub/blob/0.7.2/jupyterhub/auth.py#L128
            # but if this changes it's possible github usernames could be
            # incorrectly mapped and accepted, so lower-case only since we
            # know it's safe
            org_users.extend(u['login'].lower() for u in users)

            try:
                current = r
                r = None
                links = current.headers['Link'].split(',')
                for link in links:
                    m = re.match('<([^>]+)>;\s*rel="(\w+)"', link.strip())
                    try:
                        link_url, link_rel = m.groups()
                        if link_rel == 'next':
                            fetch_url = link_url
                            req2 = HTTPRequest(fetch_url, headers=headers)
                            self.log.debug("HTTP request %s %s", req2.url,
                                           list(req2.headers.items()))
                            r = yield http_client.fetch(req2)
                            break
                    except (AttributeError, ValueError) as e:
                        continue
            except KeyError:
                pass

        return (org_users, etag)
