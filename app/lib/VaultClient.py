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

import json

import hvac
import requests
import urllib3
from hvac.api.auth_methods import Token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VaultClient:
    def __init__(self, vault_url, jwt_token, role, mount_point):
        self.mount_point = mount_point
        self.vault_url = vault_url

        login_url = vault_url + "/v1/auth/jwt/login"

        data = '{ "jwt": "' + jwt_token + '", "role": "' + role + '" }'

        response = requests.post(login_url, data=data, verify=False)

        if not response.ok:
            raise Exception(
                "Error getting Vault token: {} - {}".format(response.status_code, response.text)
            )

        deserialized_response = json.loads(response.text)

        self.vault_auth_token = deserialized_response["auth"]["client_token"]
        self.vault_entity_id = deserialized_response["auth"]["entity_id"]

        self.client = hvac.Client(url=vault_url, token=self.vault_auth_token)
        if not self.client.is_authenticated():
            raise Exception(
                "Error authenticating against Vault with token: {}".format(self.vault_auth_token)
            )

        # ______________________________________

    def get_token(self, policy, ttl, period):
        """
        Get Vault token with specific policy
        POST '/v1/auth/token/create'
        """
        token = Token(self.client.adapter).create(policies=[policy], ttl=ttl, period=period)

        return token["auth"]["client_token"]

    def set_token(self, vault_token):
        self.client.token = vault_token
        if not self.client.is_authenticated():
            raise Exception("Error authenticating against Vault with token: {}".format(vault_token))

    def read_service_creds(self, path):
        vault_secret_path = "data/" + self.vault_entity_id + "/" + path

        try:
            secret = self.client.secrets.kv.v1.read_secret(
                path=vault_secret_path, mount_point="secret"
            )
        except hvac.exceptions.InvalidPath:
            secret = None
        return secret

    def write_service_creds(self, path, creds):
        vault_secret_path = "data/" + self.vault_entity_id + "/" + path

        self.client.secrets.kv.v1.create_or_update_secret(
            path=vault_secret_path, mount_point="secret", secret=creds
        )

    def delete_service_creds(self, path):
        vault_secret_path = "data/" + self.vault_entity_id + "/" + path

        self.client.secrets.kv.v1.delete_secret(path=vault_secret_path, mount_point="secret")

    def v1_read_secret(self, path):
        vault_secret_path = "data/" + self.vault_entity_id + "/" + path

        try:
            secret = self.client.secrets.kv.v1.read_secret(
                path=vault_secret_path, mount_point="secret"
            )
        except hvac.exceptions.InvalidPath:
            secret = None
        return secret

    def v1_write_secret(self, path, secret):
        vault_secret_path = "data/" + self.vault_entity_id + "/" + path

        self.client.secrets.kv.v1.create_or_update_secret(
            path=vault_secret_path, mount_point="secret", secret=secret
        )

    def get_wrapping_token(self, wrap_ttl, policy, ttl, period):
        """
        Get Vault wrapping token with specific policy
        POST '/v1/auth/token/create'
        """
        token = Token(self.client.adapter).create(
            policies=[policy], ttl=ttl, period=period, wrap_ttl=wrap_ttl
        )

        return token["wrap_info"]["token"]

    def write_secret_dict(self, token, secret_path, secret: dict, cas=None):
        """
        Write Secret to Vault
        POST '/v1/'+self.secrets_root+'/data/' + secret_path
        """
        if token:
            self.set_token(token)

        try:
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=secret_path, mount_point=self.mount_point, secret=secret, cas=cas
            )
        except hvac.exceptions.InvalidRequest as e:
            raise Exception("[FATAL] Unable to write vault path: {}".format(str(e)))

        return response

    def write_secret(self, token, secret_path, key, value, cas=0):
        """
        Write Secret to Vault
        POST '/v1/'+self.secrets_root+'/data/' + secret_path
        """

        secret_dict = dict()
        secret_dict[key] = value

        return self.write_secret_dict(token, secret_path, secret_dict, cas)

    def read_secret(self, token, secret_path, key):
        """
        Read Secret from Vault.
        GET '/v1/'+self.secrets_root+'/data/' + secret_path
        """
        self.set_token(token)
        try:
            secret = self.client.secrets.kv.v2.read_secret_version(
                path=secret_path, mount_point=self.mount_point
            )
        except hvac.exceptions.InvalidPath as e:
            raise Exception("[FATAL] Unable to read vault path: {}".format(str(e)))

        return secret["data"]["data"][key]

    def delete_secret(self, token, secret_path):
        """
        Permanently delete secret and metadata from Vault.
        delete_url = self.vault_url + '/v1/'+self.secrets_root+'/metadata/' + secret_path
        """
        self.set_token(token)
        self.client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=secret_path, mount_point=self.mount_point
        )

    def revoke_token(self):
        """
        Revoke (self) token
        revoke_url = self.vault_url + '/v1/auth/token/revoke-self'
        """
        Token(self.client.adapter).revoke_self()
