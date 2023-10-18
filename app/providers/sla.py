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
from flask import session

from app import cache


def get_sla_extra_info(access_token, service_id, cmdb_url):
    headers = {'Authorization': 'bearer %s' % access_token}
    url = cmdb_url + "/service/id/" + service_id
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()

    service_type = response.json()['data']['service_type']
    sitename = response.json()['data']['sitename']
    endpoint = response.json()['data'].get('endpoint')
    iam_enabled = response.json()['data'].get('iam_enabled')
    if 'properties' in response.json()['data']:
        if 'gpu_support' in response.json()['data']['properties']:
            service_type = service_type + " (gpu_support: " + \
                           str(response.json()['data']['properties']['gpu_support']) + ")"

    return sitename, endpoint, service_type, iam_enabled


def is_enabling_services(deployment_type, service_type):

    if deployment_type == "":
        return True

    if deployment_type == "CLOUD":
        return True if service_type in ["org.openstack.nova", "com.amazonaws.ec2"] else False
    elif deployment_type == "MARATHON":
        return True if "eu.indigo-datacloud.marathon" in service_type else False
    elif deployment_type == "CHRONOS":
        return True if "eu.indigo-datacloud.chronos" in service_type else False
    elif deployment_type == "QCG":
        return True if service_type == "eu.deep.qcg" else False
    else:
        return True


def make_key(*args, **kwargs):
    # create the key in the form slas:<group>
    argument = args[2] # group
    return f'slas:{argument}'


@cache.cached(timeout=30*60, make_cache_key=make_key)
def get_cached_slas(slam_url, headers, group):
    url = slam_url + "/preferences/" + group

    response = requests.get(url, headers=headers, timeout=20, verify=False)

    response.raise_for_status()
    slas = response.json()['sla']
    return slas


def get_slas(access_token, slam_url, cmdb_url, deployment_type=""):
    headers = {'Authorization': 'Bearer %s' % access_token}

    if 'active_usergroup' in session and session['active_usergroup'] is not None:
        group = session['active_usergroup']
    else:
        group = session['organisation_name']

    slas = get_cached_slas(slam_url, headers, group)

    filtered_slas = []
    for i in range(len(slas)):
        sitename, endpoint, service_type, iam_enabled = get_sla_extra_info(access_token,
                                                                           slas[i]['services'][0]['service_id'],
                                                                           cmdb_url)

        if is_enabling_services(deployment_type, service_type):
            slas[i]['service_id'] = slas[i]['services'][0]['service_id']
            slas[i]['service_type'] = service_type
            slas[i]['sitename'] = sitename
            slas[i]['endpoint'] = endpoint
            slas[i]['iam_enabled'] = iam_enabled

            filtered_slas.append(slas[i])

    return filtered_slas
