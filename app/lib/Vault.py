# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
    Class to interact with Vault for secrets management in Flask application.
"""

from app.lib.VaultClient import VaultClient


class Vault(object):
    """
    The Vault flask extension is responsible for getting and
    setting Vault secrets.
    """

    def __init__(
        self,
        app=None,
        vault_url=None,
        vault_secrets_path=None,
        vault_bound_audience=None,
        vault_role=None,
    ):
        """
        Initialize a VaultClient instance with optional configuration.

        This constructor initializes a VaultClient instance with optional configuration
        parameters for connecting to HashiCorp Vault. The configuration includes the Vault
        URL, secrets path, bound audience, and the default role to be used.

        Args:
            app (Flask, optional): The Flask application instance to initialize the client with.
            vault_url (str, optional): The URL of the HashiCorp Vault instance.
            vault_secrets_path (str, optional): The path to Vault secrets (e.g., "secret/data/my_secret").
            vault_bound_audience (str, optional): The bound audience to associate with JWTs.
            vault_role (str, optional): The default role to use for interactions with Vault.

        Attributes:
            vault_url (str): The URL of the HashiCorp Vault instance.
            vault_secrets_path (str): The path to Vault secrets.
            vault_bound_audience (str): The bound audience for JWTs.
            vault_role (str): The default role for Vault interactions.
            _client (VaultClient, optional): An internal VaultClient instance for interacting with Vault.
            app (Flask, optional): The Flask application instance.
        """
        self.vault_url = vault_url
        self.vault_secrets_path = vault_secrets_path
        self.vault_bound_audience = vault_bound_audience
        self.vault_role = vault_role

        self._client = None
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Init the Flask_Vault extension"""
        if self.vault_url is None:
            self.vault_url = app.config.get("VAULT_URL", "")
        if self.vault_secrets_path is None:
            self.vault_secrets_path = app.config.get("VAULT_SECRETS_PATH", "secrets")
        if self.vault_bound_audience is None:
            self.vault_bound_audience = app.config.get("VAULT_BOUND_AUDIENCE", "")
        if self.vault_role is None:
            self.vault_role = app.config.get("VAULT_ROLE", "")

    def connect(self, token, role=None):
        """
        Connect to a HashiCorp Vault instance with the specified token and optional role.

        Args:
            token (str): The authentication token used to access HashiCorp Vault.
            role (str, optional): The role to assume when interacting with the Vault.
                                If not provided, the role associated with the VaultClient
                                instance will be used.

        Returns:
            VaultClient: An instance of the VaultClient class for interacting with HashiCorp Vault.
        """
        if role is None:
            role = self.vault_role
        return VaultClient(self.vault_url, token, role, self.vault_secrets_path)