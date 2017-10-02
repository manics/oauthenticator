import json
import os

c.JupyterHub.spawner_class = 'imagespawner.DockerImageChooserSpawner'

c.JupyterHub.ip = '0.0.0.0'
#c.JupyterHub.proxy_api_ip = c.JupyterHub.hub_ip
# Jupyterhub 0.7.2:
c.JupyterHub.hub_connect_ip = '172.17.0.1'
# Jupyterhub 0.8.0:
c.DockerSpawner.hub_ip_connect = '172.17.0.1'
#c.JupyterHub.hub_ip = '172.17.0.1'
c.DockerSpawner.use_internal_ip = True
#c.JupyterHub.proxy_api_ip = '172.17.0.1'
#c.JupyterHub.ip = '172.17.0.1'

# The admin must pull these before they can be used.
c.DockerImageChooserSpawner.dockerimages = [
    'test-base-notebook',
    'test-minimal-notebook',
]

#c.JupyterHub.proxy_auth_token = os.getenv('IDR_JUPYTER_PROXY_TOKEN', '')
c.JupyterHub.base_url = '/jupyter/'

# Whitespace separated list of users
c.Authenticator.whitelist = os.getenv('IDR_JUPYTER_USERS', '').split()
# Whitespace separated list of admins
c.Authenticator.admin_users = os.getenv('IDR_JUPYTER_ADMINS', '').split()

# The authenticator class
# You can set this to dummyauthenticator.DummyAuthenticator for testing
c.JupyterHub.authenticator_class = 'oauthenticator.elixir.ElixirOAuthenticator'

c.ElixirOAuthenticator.oauth_callback_url = 'http://localhost:8000/jupyter/hub/oauth_callback'
c.ElixirOAuthenticator.client_id = ''
c.ElixirOAuthenticator.client_secret = ''

c.Spawner.environment = {
    'PARENT_HOSTNAME': os.getenv('HOSTNAME', ''),
}
