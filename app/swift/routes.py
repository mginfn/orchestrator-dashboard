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
import random
import string

from flask import Blueprint, render_template, request, flash, session
from app import app, iam_blueprint
from app.lib import auth, openstack, utils, s3 as s3utils
from .swift import Swift
from werkzeug.exceptions import Forbidden
import logging


swift_bp = Blueprint('swift_bp', __name__, template_folder='templates', static_folder='static')


@swift_bp.route('/createswifttoken', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def createswifttoken():
    if request.method == 'POST':
        logging.debug("Form data: " + json.dumps(request.form.to_dict()))
        form_data = request.form.to_dict()
        swift_a = form_data["swiftauthurl"] if "swiftauthurl" in form_data else None
        swift_v = form_data["swiftauthversion"] if "swiftauthversion" in form_data else None
        swift_u = form_data["swiftuser"] if "swiftuser" in form_data else None
        swift_k = form_data["swiftkey"] if "swiftkey" in form_data else None
        swift_t = form_data["swifttenant"] if "swifttenant" in form_data else None
        swift_b = form_data["swifcontainer"] if "swifcontainer" in form_data else None

        if swift_a and swift_v and swift_u and swift_k and swift_t and swift_b:
            swift = Swift()
            t = "OS" + "§" \
                + swift_a + "§" \
                + swift_v + "§" \
                + swift_u + "§" \
                + swift_k + "§" \
                + swift_t + "§" \
                + swift_b
            token = swift.pack(t)
            return render_template('createswifttoken.html', token=token)
        else:
            flash("All fields must be filled! Cannot create swift token.", 'danger')
    return render_template('createswifttoken.html')


@swift_bp.route('/gets3creds', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
def gets3creds():
    s3_endpoints = app.config.get("S3_ENDPOINTS")
    urls = [u['url'] for u in s3_endpoints]

    if request.method == 'POST':
        app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))
        form_data = request.form.to_dict()
        s3_url = form_data["s3url"]
        group = form_data["project"]
        s3params = next(s3 for s3 in s3_endpoints if s3['url'] == s3_url)
        auth_url = s3params['auth_url']
        idp_name = s3params['auth_idp_name']
        idp_protocol = s3params['auth_idp_protocol']
        project = next((m['project'] for m in s3params['mapping'] if m['group'] == group), None)
        
        if not project:
            app.logger.error("Get S3 creds error: project for group {} not found".format(group))
            flash(" Sorry, something went wrong while getting S3 credentials: project {} not found".format(group), 'danger')
            return render_template('s3creds.html', s3urls=urls)

        access_token = iam_blueprint.session.token['access_token']
        access, secret = openstack.get_or_create_ec2_creds(access_token, project, auth_url,
                                                           identity_provider=idp_name, protocol=idp_protocol)
        if access and secret:
            # test access
            try:
                bucket = 'test' + ''.join(random.choice(string.ascii_lowercase) for i in range(8))
                s3utils.create_bucket(access, secret, s3_url, bucket)
                s3utils.delete_bucket(access, secret, s3_url, bucket)
            except Forbidden as e:
                app.logger.error("Error while testing S3 credentials for user {}, group {}: {}"
                                 .format(session['username'], project, e))
                flash(" Sorry, your request needs a special authorization. "
                      "A notification has been sent automatically to the support team. "
                      "You will be contacted soon.", 'danger')
                utils.send_authorization_request_email("S3 credentials for project {}".format(project))
                return render_template('s3creds.html', s3urls=urls)

            return render_template('s3creds.html', s3creds=dict(access_key=access, secret_key=secret))
        else:
            app.logger.error("Null S3 credentials returned for user {}, group {}"
                             .format(session['username'], project))
            flash(" Sorry, something went wrong while getting S3 credentials for project {}".format(group), 'danger')
    return render_template('s3creds.html', s3urls=urls)
