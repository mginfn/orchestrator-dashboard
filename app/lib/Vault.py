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

from .VaultClient import VaultClient


class Vault(object):
    """
    The Vault flask extension is responsible for getting and
    setting Vault secrets.
    """

    def __init__(self, app=None, vault_url=None, vault_secrets_path=None, vault_bound_audience=None, vault_role=None):

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
            self.vault_url = app.config.get("VAULT_URL", '')
        if self.vault_secrets_path is None:
            self.vault_secrets_path = app.config.get("VAULT_SECRET_PATH", 'secret')
        if self.vault_bound_audience is None:
            self.vault_bound_audience = app.config.get("VAULT_BOUND_AUDIENCE", '')
        if self.vault_role is None:
            self.vault_role = app.config.get("VAULT_ROLE", '')

    def connect(self, token, role=None):
        if role is None:
            role = self.vault_role
        return VaultClient(self.vault_url, token, role)

