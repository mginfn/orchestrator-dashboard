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

import ast
from functools import wraps

import requests
from flask import current_app as app
from flask import json, redirect, render_template, session, url_for

from app.iam import iam
from app.lib import utils


def set_user_info():
    account_info = iam.get("/userinfo")
    account_info_json = account_info.json()
    user_groups = account_info_json["groups"]
    user_id = account_info_json["sub"]

    supported_groups = []
    if app.settings.iam_groups:
        supported_groups = list(set(app.settings.iam_groups) & set(user_groups))
        if len(supported_groups) == 0:
            app.logger.warning(
                "The user {} does not belong to any supported user group".format(user_id)
            )

    session["userid"] = user_id
    session["username"] = account_info_json["name"]
    session["preferred_username"] = account_info_json["preferred_username"]
    session["given_name"] = account_info_json["given_name"]
    session["family_name"] = account_info_json["family_name"]
    session["useremail"] = account_info_json["email"]
    session["userrole"] = "user"
    session["gravatar"] = utils.avatar(account_info_json["email"], 26)
    session["organisation_name"] = account_info_json["organisation_name"]
    session["usergroups"] = user_groups
    session["supported_usergroups"] = supported_groups
    if "active_usergroup" not in session:
        session["active_usergroup"] = next(iter(supported_groups), None)

    iam_configuration = iam.get(".well-known/openid-configuration").json()
    session["iss"] = iam_configuration["issuer"]


def update_user_info():
    account_info = iam.get("/userinfo")
    account_info_json = account_info.json()
    user_groups = account_info_json["groups"]
    user_id = account_info_json["sub"]

    supported_groups = []
    if app.settings.iam_groups:
        supported_groups = list(set(app.settings.iam_groups) & set(user_groups))
        if len(supported_groups) == 0:
            app.logger.warning(
                "The user {} does not belong to any supported user group".format(user_id)
            )

    session["usergroups"] = user_groups
    session["supported_usergroups"] = supported_groups
    if "active_usergroup" not in session:
        session["active_usergroup"] = next(iter(supported_groups), None)


def authorized_with_valid_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not iam.authorized or "username" not in session:
            return redirect(url_for("iam.login"))

        if iam.token["expires_in"] < 60:
            app.logger.debug("Token will expire soon...Refresh token")
            update_user_info()

        return f(*args, **kwargs)

    return decorated_function


def only_for_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session["userrole"].lower() == "admin":
            return render_template(app.config.get("HOME_TEMPLATE"))

        return f(*args, **kwargs)

    return decorated_function


def exchange_token_with_audience(iam_url, client_id, client_secret, iam_token, audience):
    payload_string = (
        '{ "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": "'
        + audience
        + '", "subject_token": "'
        + iam_token
        + '", "scope": "openid profile" }'
    )

    # Convert string payload to dictionary
    payload = ast.literal_eval(payload_string)

    iam_response = requests.post(
        iam_url + "/token", data=payload, auth=(client_id, client_secret), verify=False
    )

    if not iam_response.ok:
        raise Exception(
            "Error exchanging token: {} - {}".format(iam_response.status_code, iam_response.text)
        )

    deserialized_iam_response = json.loads(iam_response.text)

    return deserialized_iam_response["access_token"]
