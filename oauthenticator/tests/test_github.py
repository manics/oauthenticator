from pytest import fixture, mark

from ..github import GitHubOAuthenticator, GitHubLoginHandler

from .mocks import setup_oauth_mock, no_code_test, mock_handler


def user_model(username):
    """Return a user model"""
    return {
        'login': username,
    }

@fixture
def github_client(client):
    setup_oauth_mock(client,
        host=['github.com', 'api.github.com'],
        access_token_path='/login/oauth/access_token',
        user_path='/user',
        token_type='token',
    )
    return client


@mark.gen_test
def test_github(github_client):
    authenticator = GitHubOAuthenticator()
    handler = github_client.handler_for_user(user_model('wash'))
    name = yield authenticator.authenticate(handler)
    assert name == 'wash'


@mark.gen_test
def test_no_code(github_client):
    yield no_code_test(GitHubOAuthenticator())


@mark.gen_test
def test_github_multiple_tokens(github_client):
    authenticator = GitHubOAuthenticator()
    authenticator.client_id = 'id'
    authenticator.client_id_hostmap = {
        'a.example.org': 'ida',
    }
    authenticator.client_secret = 'secret'
    authenticator.client_secret_hostmap = {
        'a.example.org': 'secreta',
    }
    authenticator.oauth_callback_url = 'http://example.org/cb'
    authenticator.oauth_callback_url_hostmap = {
        'a.example.org': 'http://a.example.org/cba',
    }

    handler = github_client.handler_for_user(user_model('dummy'))
    handler.request.host = 'a.example.org'

    assert authenticator.get_client_id() == 'id'
    assert authenticator.get_client_id(handler) == 'ida'
    assert authenticator.get_client_secret() == 'secret'
    assert authenticator.get_client_secret(handler) == 'secreta'
    assert authenticator.get_callback_url() == 'http://example.org/cb'
    assert authenticator.get_callback_url(handler) == \
        'http://a.example.org/cba'

    # NOTE: This doesn't test that these methods are called correctly
