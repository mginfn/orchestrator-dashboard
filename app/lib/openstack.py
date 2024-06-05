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
import requests


def get_unscoped_keystone_token(
    access_token, auth_url, identity_provider="infn-cc", protocol="oidc", **kwargs
):
    """Get an unscoped keystone token using an access token (issued by an OpenID Connect IdP).

    Parameters
    ----------
    access_token : str
        The bearer token
    identity_provider : str, optional
        the name of the identity provider as configured in keystone (default is infn-cc)
    protocol: str, optional
        the id of the protocol as configured in keystone (default is oidc)

    Returns
    -------
    str
        the generated unscoped token
    """

    headers = {"Authorization": "bearer %s" % access_token}

    url = auth_url + "/v3/OS-FEDERATION/identity_providers/{}/protocols/{}/auth".format(
        identity_provider, protocol
    )

    response = requests.post(url, headers=headers)
    response.raise_for_status()

    token = response.headers.get("X-Subject-Token")
    user_id = response.json().get("token").get("user").get("id")

    return token, user_id


def get_project_list(auth_url, unscoped_token):
    """Get the list of projects the user is authorized to access

    Parameters
    ----------
    unscoped_token : str
        The unscoped token

    Returns
    -------
    list
        the list of projects
    """
    headers = {"X-Auth-Token": unscoped_token}

    url = auth_url + "/v3/auth/projects"

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    return response.json().get("projects")


def get_scoped_token(auth_url, unscoped_token, project_id):
    """Get a scoped (tenant-specific) keystone token using an unscoped token.

    Parameters
    ----------
    unscoped_token : str
        The unscoped token
    project_id : str
        the id of the project that will the scope of the token

    Returns
    -------
    str
        the generated scoped token
    """

    payload = {
        "auth": {
            "identity": {"methods": ["token"], "token": {"id": unscoped_token}},
            "scope": {"project": {"id": project_id}},
        }
    }
    headers = {"Content-Type": "application/json"}

    url = auth_url + "/v3/auth/tokens"

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    response.raise_for_status()

    return response.headers.get("X-Subject-Token")


def list_ec2_credentials(auth_url, user_id, project_id, scoped_token):
    """Get the list of EC2 credentials for the given user in the given project, if they already exist.

    Parameters
    ----------
    user_id : str
        The id of the user
    project_id : str
        the id of the project
    scoped_token:
        the user token

    Returns
    -------
    list
        the list of EC2 credentials if any
    """
    headers = {"Content-Type": "application/json", "X-Auth-Token": scoped_token}

    url = auth_url + "/v3/users/{}/credentials/OS-EC2".format(user_id)

    response = requests.get(url, headers=headers)

    credentials = []
    if response.ok:
        ec2_creds = response.json().get("credentials")
        credentials = [
            creds for creds in ec2_creds if creds.get("tenant_id") == project_id
        ]

    return credentials


def create_ec2_credentials(auth_url, user_id, project_id, scoped_token):
    """Create EC2 credentials for the given user in the given project.

    Parameters
    ----------
    user_id : str
        The id of the user
    project_id : str
        the id of the project
    scoped_token:
        the user token

    Returns
    -------
    list
        the list of EC2 credentials
    """
    payload = {"tenant_id": project_id}
    headers = {"Content-Type": "application/json", "X-Auth-Token": scoped_token}

    url = auth_url + "/v3/users/{}/credentials/OS-EC2".format(user_id)

    response = requests.post(url, data=json.dumps(payload), headers=headers)

    credential = None
    if response.ok:
        credential = response.json().get("credential")

    return credential


def get_or_create_ec2_creds(
    access_token, project, auth_url, identity_provider="infn-cc", protocol="oidc"
):
    """Get EC2 credentials from access token. If some EC2 credentials are already available, they will be re-used.
    Otherwise new credentials will be generated

    Parameters
    ----------
    access_token : str
        The user access token issued by the OpenID Connect IdP
    project : str
        The project the credentials must be valid for
    identity_provider : str
        the identity provider as configured in keystone (default is infn-cc)
    protocol:
        the protocol as configured in keystone (default is oidc)

    Returns
    -------
    access: str
        credential access key
    secret: str
        credential secret
    """

    unscoped_token, user_id = get_unscoped_keystone_token(
        access_token, auth_url, identity_provider, protocol
    )

    access = None
    secret = None

    if unscoped_token:
        projects = get_project_list(auth_url, unscoped_token)
        prj = next(filter(lambda prj: prj.get("name") == project, projects), None)
        project_id = prj.get("id") if prj else None

        if project_id:
            scoped_token = get_scoped_token(auth_url, unscoped_token, project_id)

            credentials = list_ec2_credentials(
                auth_url, user_id, project_id, scoped_token
            )

            if not credentials:
                credentials = [
                    create_ec2_credentials(auth_url, user_id, project_id, scoped_token)
                ]

            if credentials:
                access = credentials[0].get("access")
                secret = credentials[0].get("secret")

    return access, secret


def delete_ec2_credential(auth_url, user_id, credential_id, scoped_token):
    """Delete EC2 credential for given user.

    Parameters
    ----------
    user_id : str
        The id of the user
    credential_id : str
        the id (access key) of the credential to be deleted
    scoped_token:
        the scoped token of the user

    """

    headers = {"Accept": "application/json", "X-Auth-Token": scoped_token}

    url = auth_url + "/v3/users/{}/credentials/OS-EC2/{}".format(user_id, credential_id)

    requests.delete(url, headers=headers)


def delete_ec2_creds(
    access_token, project, auth_url, identity_provider="infn-cc", protocol="oidc"
):
    """Delete EC2 credential using the user access token issued by an OpenID Connect IdP

    Parameters
    ----------
    access_token : str
        The user access token issued by the OpenID Connect IdP
    project : str
        The project the credentials must be valid for
    identity_provider : str
        the identity provider as configured in keystone (default is infn-cc)
    protocol:
        the protocol as configured in keystone (default is oidc)

    """
    unscoped_token, user_id = get_unscoped_keystone_token(
        access_token, auth_url, identity_provider, protocol
    )

    if unscoped_token:
        projects = get_project_list(auth_url, unscoped_token)
        prj = next(filter(lambda prj: prj.get("name") == project, projects), None)
        project_id = prj.get("id") if prj else None

        if project_id:
            scoped_token = get_scoped_token(auth_url, unscoped_token, project_id)

            credentials = list_ec2_credentials(
                auth_url, user_id, project_id, scoped_token
            )

            if credentials:
                for cred in credentials:
                    delete_ec2_credential(
                        auth_url, user_id, cred.get("access"), scoped_token
                    )

def get_openstack_ec2_creds(
    access_token, project, auth_url, identity_provider="infn-cc", protocol="oidc"
):
    """Get EC2 credentials from access token. If some EC2 credentials are already available, they will be re-used.
    Otherwise new credentials will be generated

    Parameters
    ----------
    access_token : str
        The user access token issued by the OpenID Connect IdP
    project : str
        The project the credentials must be valid for
    identity_provider : str
        the identity provider as configured in keystone (default is infn-cc)
    protocol:
        the protocol as configured in keystone (default is oidc)

    Returns
    -------
    access: str
        credential access key
    secret: str
        credential secret
    """

    unscoped_token, user_id = get_unscoped_keystone_token(
        access_token, auth_url, identity_provider, protocol
    )

    if unscoped_token:
        projects = get_project_list(auth_url, unscoped_token)
        prj = next(filter(lambda prj: prj.get("name") == project, projects), None)
        project_id = prj.get("id") if prj else None

        if project_id:
            scoped_token = get_scoped_token(auth_url, unscoped_token, project_id)

            return scoped_token