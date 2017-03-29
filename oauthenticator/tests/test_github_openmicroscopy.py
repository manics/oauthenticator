from pytest import mark

from ..github import GitHubOrgOAuthenticator

#import logging
#logging.basicConfig(level=logging.DEBUG)


@mark.gen_test
@mark.parametrize("username,ismember", [
    ('not-in-org', False),
    ('jrswedlow', True),
])
def test_check_whitelist(username, ismember):
    authenticator = GitHubOrgOAuthenticator()
    authenticator.organisation_whitelist = 'openmicroscopy'
    found = yield authenticator.check_whitelist(username)
    assert found == ismember
