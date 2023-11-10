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

from flask import g
from werkzeug.local import LocalProxy

from flask_dance.consumer import OAuth2ConsumerBlueprint


def make_iam_blueprint(
        client_id=None,
        client_secret=None,
        base_url=None,
        redirect_to=None):
    """
    Create an OAuth2 blueprint for integrating with an IAM service.

    This function creates an OAuth2 blueprint using Flask-Dance for integrating your
    application with an Identity and Access Management (IAM) service. It allows users
    to log in and authorize your application to access their IAM data. You can provide
    the necessary configuration parameters to establish the connection with the IAM
    service.

    Args:
        client_id (str, optional): The client ID for your application.
        client_secret (str, optional): The client secret for your application.
        base_url (str, optional): The base URL for the IAM service.
        token_url (str, optional): The URL to obtain OAuth2 tokens.
        auto_refresh_url (str, optional): The URL to automatically refresh tokens.
        authorization_url (str, optional): The URL to initiate the OAuth2 authorization process.
        redirect_to (str, optional): The URL to redirect to after successful authentication.

    Returns:
        OAuth2ConsumerBlueprint: A Flask-Dance OAuth2 blueprint for IAM integration.
    """
    iam_bp = OAuth2ConsumerBlueprint(
        "iam", __name__,
        client_id=client_id,
        client_secret=client_secret,
        base_url=base_url,
        token_url=base_url + '/token',
        auto_refresh_url=base_url + '/token',
        authorization_url=base_url + '/authorize',
        redirect_to=redirect_to
    )

    @iam_bp.before_app_request
    def set_applocal_session():
        g.flask_dance_iam = iam_bp.session

    return iam_bp

iam = LocalProxy(lambda: g.flask_dance_iam)
