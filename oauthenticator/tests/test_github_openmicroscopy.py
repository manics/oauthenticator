from pytest import mark
from os import getenv

from ..github import GitHubOrgOAuthenticator

#import logging
#logging.basicConfig(level=logging.DEBUG)


# This is likely to fail on Travis due to Github rate limits:
# https://developer.github.com/v3/#rate-limiting
@mark.xfail(
    getenv('TRAVIS') == 'true',
    reason="Travis exceeds Github API rate limits"
)
@mark.gen_test
@mark.parametrize("username,ismember", [
    ('not-in-org', False),
    ('jrswedlow', True),
])
def test_check_whitelist(username, ismember):
    authenticator = GitHubOrgOAuthenticator()
    authenticator.github_organization_whitelist = ['openmicroscopy']
    found = yield authenticator.check_whitelist(username)
    assert found == ismember
