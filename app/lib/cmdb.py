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

import requests


class Cmdb:
    def __init__(self, cmdb_url, timeout=60):
        self.url = cmdb_url
        self.timeout = timeout

    # @cache.cached(timeout=30 * 60)
    def get_service(self, access_token, service_id):
        headers = {"Authorization": "Bearer %s" % access_token}

        url = self.url + "/service/id/" + service_id
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()

        data = response.json()["data"]
        data["id"] = response.json()["_id"]
        return data

    def get_services(self, access_token, service_type=""):
        headers = {"Authorization": "Bearer %s" % access_token}

        if service_type:
            url = self.url + "/service/filters/type/" + service_type
        else:
            url = self.url + "/service/list"

        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()

        services = response.json()["rows"]

        ss = [self.get_service(access_token, s["id"]) for s in services]

        return ss

    def get_service_by_endpoint(self, access_token, endpoint):
        services = self.get_services(access_token)
        service = next((s for s in services if s["endpoint"] == endpoint), None)
        return service

    def get_service_projects(self, access_token, service_id):
        headers = {"Authorization": "Bearer %s" % access_token}

        url = self.url + "/service/id/" + service_id + "/has_many/tenants"
        response = requests.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        projects = response.json()["rows"]

        return [p["value"] for p in projects]

    def get_service_project(self, access_token, issuer, service, group):
        """
        Retrieve the project associated with a specific service and group,
        along with the matching IDP.

        Parameters:
            access_token (str): The access token for authentication.
            issuer (str): The issuer to match against the supported IDPs of the service.
            service (dict or object): The service object.
            group (str): The IAM organization group to match against the project.

        Returns:
            tuple: A tuple containing the project associated with the group and the matching IDP.
                The first element is the project dictionary or None if not found.
                The second element is the matching IDP dictionary or None if not found.

        Example of matching IDP dictionary structure:
            {
                "protocol": "openid",
                "name": "infn-cloud",
                "issuer": "https://iam.cloud.infn.it/"
            }
        """
        # Fetch the service using auth_url if available, else use the provided service directly
        service_tmp = self.get_service_by_endpoint(access_token, service.get("auth_url", None))

        s = (
            service_tmp if service_tmp is not None else service
        )

        if not s:
            return None, None

        # Find the supported IDP that matches the issuer
        matching_idp = next(
            (idp for idp in s.get("supported_idps", []) if idp.get("issuer", "") == issuer), None
        )
        if not matching_idp:
            return None, None

        projects = self.get_service_projects(access_token, s.get("id"))
        project = next((p for p in projects if p.get("iam_organisation", "") == group), None)

        return project, matching_idp
