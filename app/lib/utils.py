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
from app import app, mail
from flask_mail import Message
from threading import Thread
from flask import session, render_template
from markupsafe import Markup


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
    return '' if (s is None or s == '') else str(s)


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


def send_authorization_request_email(service_type, **kwargs):
    user_email = kwargs['email'] if 'email' in kwargs else ""
    message = kwargs['message'] if 'message' in kwargs else ""
    message = Markup(
        "The following user has requested access for service \"{}\": <br>username: {} " \
        "<br>IAM id (sub): {} <br>IAM groups: {} <br>email registered in IAM: {} " \
        "<br>email provided by the user: {} " \
        "<br>Message: {}".format(service_type, session['username'], session['userid'],
                                 session['usergroups'], session['useremail'], user_email, message))

    sender = kwargs['email'] if 'email' in kwargs else session['useremail']
    send_email("New Authorization Request",
               sender=sender,
               recipients=[app.config.get('SUPPORT_EMAIL')],
               html_body=message)

def send_ports_request_email(deployment_uuid, **kwargs):
    user_email = kwargs['email'] if 'email' in kwargs else ""
    message = kwargs['message'] if 'message' in kwargs else ""
    message = Markup(
        "The following user has requested to open further ports for deployment \"{}\": <br>username: {} " \
        "<br>IAM id (sub): {} <br>email registered in IAM: {} " \
        "<br>email provided by the user: {} " \
        "<br>Message: {}".format(deployment_uuid, session['username'], session['userid'],
                                  session['useremail'], user_email, message))

    sender = kwargs['email'] if 'email' in kwargs else session['useremail']
    send_email("New Ports Request",
               sender=sender,
               recipients=[app.config.get('SUPPORT_EMAIL')],
               html_body=message)

def create_and_send_email(subject, sender, recipients, uuid, status):
    send_email(subject,
               sender=sender,
               recipients=recipients,
               html_body=render_template(app.config.get('MAIL_TEMPLATE'), uuid=uuid, status=status))


def send_email(subject, sender, recipients, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    msg.body = "This email is an automatic notification"  # Add plain text, needed to avoid MPART_ALT_DIFF with AntiSpam
    Thread(target=send_async_email, args=(app, msg)).start()


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)
