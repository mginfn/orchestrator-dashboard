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

def next_url(links):
    link = [i for i in links if i['rel'] == 'next']
    return link[0]['href'] if link else None

# manage pagination
def get_all_results(url, timeout=60, headers={}, params={}, results=[]):
    while True:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        links = response.json()["links"]
        results.extend(response.json()["content"])
        url = next_url(links)

        if not url:
            break


class Orchestrator():

    def __init__(self, orchestrator_url, timeout=60):
        self.orchestrator_url = orchestrator_url
        self.timeout = timeout

    def get_deployments(self, access_token, created_by=None, user_group=None):
        headers = {'Authorization': 'Bearer %s' % access_token}
        params = []
        if created_by:
            params.append("createdBy={}".format(created_by))
        if user_group:
            params.append("userGroup={}".format(user_group))

        str_params = ""
        if params:
            str_params = "?{}".format("&".join(params))

        deployments = []
        url = self.orchestrator_url + "/deployments" + str_params

        try:
          get_all_results(url, headers=headers, timeout=self.timeout, results=deployments)
        except Exception as e:
            raise Exception("Error retrieving deployment list: {}".format(str(e)))
        return deployments

    def get_template(self, access_token, deployment_uuid) -> str:
        headers = {'Authorization': 'Bearer %s' % access_token}
        url = self.orchestrator_url + "/deployments/" + deployment_uuid + "/template"

        response = requests.get(url, headers=headers, timeout=self.timeout)

        if not response.ok:
            raise Exception("Error getting template for deployment {}: {}".format(deployment_uuid, response.text))
        return response.text

    def get_log(self, access_token, deployment_uuid) -> str:
        headers = {'Authorization': 'Bearer %s' % access_token}
        url = self.orchestrator_url + "/deployments/" + deployment_uuid + "/log"

        response = requests.get(url, headers=headers, timeout=self.timeout)

        if not response.ok:
            raise Exception("Error getting log for deployment {}: {}".format(deployment_uuid, response.text))
        return response.text

    def get_extra_info(self, access_token, deployment_uuid) -> str:
        headers = {'Authorization': 'Bearer %s' % access_token}
        url = self.orchestrator_url + "/deployments/" + deployment_uuid + "/extrainfo"

        response = requests.get(url, headers=headers, timeout=self.timeout)

        if not response.ok:
            raise Exception("Error getting extra information for deployment {}: {}".format(deployment_uuid, response.text))
        return response.text

    def get_resources(self, access_token, deployment_uuid):
        headers = {'Authorization': 'Bearer %s' % access_token}
        url = self.orchestrator_url + "/deployments/" + deployment_uuid + "/resources"

        resources = []
        try:
            get_all_results(url=url, timeout=self.timeout, headers=headers, results=resources)
        except Exception as e:
            raise Exception("Error retrieving resources list for deployment {}: {}".format(deployment_uuid, str(e)))
        return resources

    def post_action(self, access_token, deployment_uuid, resource_uuid, action):
        headers = {'Authorization': 'Bearer %s' % access_token}

        url = self.orchestrator_url + "/deployments/" + deployment_uuid + "/resources/" + resource_uuid + "/actions"
        response = requests.post(url, timeout=self.timeout, headers=headers, json={"type": action})

        if not response.ok:
            raise Exception("Error performing {} action on deployment {}: {}".format(action, deployment_uuid, response.text))

    def create(self, access_token, user_group, template, inputs, keep_last_attempt, provider_timeout_mins, timeout_mins, callback):

        url = self.orchestrator_url + "/deployments/"
        headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}

        params = {}
        if user_group:
            params['userGroup'] = user_group
        params['keepLastAttempt'] = str(bool(keep_last_attempt)).lower()
        params['providerTimeoutMins'] = provider_timeout_mins
        params['timeoutMins'] = timeout_mins
        params['callback'] = callback

        payload = {"template": template, "parameters": inputs}
        payload.update(params)

        response = requests.post(url,timeout=self.timeout, json=payload, headers=headers)

        if not response.ok:
            raise Exception("Error creating deployment: {}".format(response.text))

        return response.json()

    def update(self, access_token, deployment_uuid, template, inputs, keep_last_attempt, provider_timeout_mins, timeout_mins, callback):
        url = self.orchestrator_url + "/deployments/" + deployment_uuid
        headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}

        params = {}
        params['keepLastAttempt'] = str(bool(keep_last_attempt)).lower()
        params['providerTimeoutMins'] = provider_timeout_mins
        params['timeoutMins'] = timeout_mins
        params['callback'] = callback

        payload = {"template": template, "parameters": inputs}
        payload.update(params)

        response = requests.put(url, timeout=self.timeout, json=payload, headers=headers)
        if not response.ok:
            raise Exception("Error updating deployment: {}: {}".format(deployment_uuid, response.text))

    def delete(self, access_token, deployment_uuid):
        headers = {'Authorization': 'Bearer %s' % access_token}
        url = self.orchestrator_url + "/deployments/" + deployment_uuid
        response = requests.delete(url, timeout=self.timeout, headers=headers)
        if not response.ok:
            raise Exception("Error deleting deployment {}: {}".format(deployment_uuid, response.text))





