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
import linecache
import sys
import re
import string
import secrets
from hashlib import md5
from app import app


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


def intersect(a, b):
    return set(a).intersection(b)


def extract_netinterface_ips(input):
    res = {}
    for key,value in input.items():
        if re.match("net_interface.[0-9].ip", key):
            new_key = key.replace('.','_')
            res[new_key] = value

    return res

def xstr(s):
    return '' if s is None else str(s)


def nnstr(s):
    return '' if (s is None or s is '') else str(s)


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


def logexception(err):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    app.logger.error('{} at ({}, LINE {} "{}"): {}'.format(err, filename, lineno, line.strip(), exc_obj))


def getorchestratorversion(orchestrator_url):
    url = orchestrator_url + "/info"
    response = requests.get(url)

    return response.json()['build']['version']


def getorchestratorconfiguration(orchestrator_url, access_token):
    headers = {'Authorization': 'bearer %s' % access_token}

    url = orchestrator_url + "/configuration"
    response = requests.get(url, headers=headers)

    configuration = {}
    if response.ok:
        configuration = response.json()

    return configuration

def format_json_radl(vminfo):
    res = {}
    for elem in vminfo:
        if elem["class"] == "system":
            for field, value in elem.items():
                if field not in ["class", "id"]:
                    if field.endswith("_min"):
                        field = field[:-4]
                    res[field] = value

    return res


def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ""
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(10))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break

    return password
