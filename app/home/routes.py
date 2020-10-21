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

from .. import app, iam_blueprint, mail, tosca
from app.lib import utils, auth, settings, dbhelpers, openstack
from app.models.User import User
from markupsafe import Markup
from werkzeug.exceptions import Forbidden
from flask import Blueprint, json, render_template, request, redirect, url_for, session, make_response
from flask_mail import Message
from threading import Thread
import json


iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json
app.jinja_env.filters['extract_netinterface_ips'] = utils.extract_netinterface_ips

toscaInfo = tosca.tosca_info

app.logger.debug("TOSCA INFO: " + json.dumps(toscaInfo))
app.logger.debug("TOSCA DIR: " + tosca.tosca_dir)

home_bp = Blueprint('home_bp', __name__, template_folder='templates', static_folder='static')

@home_bp.route('/settings')
@auth.authorized_with_valid_token
def show_settings():
    return render_template('settings.html',
                           iam_url=settings.iamUrl,
                           orchestrator_url=settings.orchestratorUrl,
                           orchestrator_conf=settings.orchestratorConf,
                           vault_url=app.config.get('VAULT_URL'))


@home_bp.route('/login')
def login():
    session.clear()
    return render_template(app.config.get('HOME_TEMPLATE'))


def check_template_access(allowed_groups, user_groups):

    # check intersection of user groups with user membership
    if (set(allowed_groups.split(',')) & set(user_groups)) != set() or allowed_groups == '*':
        return True
    else:
        return False


@app.route('/')
@home_bp.route('/')
def home():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('home_bp.login'))

    account_info = iam_blueprint.session.get("/userinfo")

    if account_info.ok:
        account_info_json = account_info.json()
        user_groups = account_info_json['groups']

        if settings.iamGroups:
            if set(settings.iamGroups)&set(user_groups) == set():
                app.logger.debug("No match on group membership. User group membership: "
                                 + json.dumps(user_groups))
                message = Markup(
                    'Your identity has been verified successfully, but you are not authorized to access the services.<br>' +
                    'Please, contact the administrators ({}) in order to get proper permissions'.format(app.config.get('SUPPORT_EMAIL')))
                raise Forbidden(description=message)

        session['userid'] = account_info_json['sub']
        session['username'] = account_info_json['name']
        session['useremail'] = account_info_json['email']
        session['userrole'] = 'user'
        session['gravatar'] = utils.avatar(account_info_json['email'], 26)
        session['organisation_name'] = account_info_json['organisation_name']
        # access_token = iam_blueprint.session.token['access_token']

        # check database
        # if user not found, insert
        #
        app.logger.info(dir(User))
        user = dbhelpers.get_user(account_info_json['sub'])
        if user is None:
            email = account_info_json['email']
            admins = json.dumps(app.config['ADMINS'])
            role = 'admin' if email in admins else 'user'

            user = User(sub=account_info_json['sub'],
                        name=account_info_json['name'],
                        username=account_info_json['preferred_username'],
                        given_name=account_info_json['given_name'],
                        family_name=account_info_json['family_name'],
                        email=email,
                        organisation_name=account_info_json['organisation_name'],
                        picture=utils.avatar(email, 26),
                        role=role,
                        active=1)
            dbhelpers.add_object(user)

        session['userrole'] = user.role  # role

        templates = {k: v for (k, v) in toscaInfo.items() if
                     check_template_access(v.get("metadata").get("allowed_groups"), user_groups)}

        return render_template(app.config.get('PORTFOLIO_TEMPLATE'), templates=templates)


@home_bp.route('/logout')
def logout():
    session.clear()
    iam_blueprint.session.get("/logout")
    return redirect(url_for('home_bp.login'))


@app.route('/callback', methods=['POST'])
def callback():
    payload = request.get_json()
    app.logger.info("Callback payload: " + json.dumps(payload))

    status = payload['status']
    task = payload['task']
    uuid = payload['uuid']
    providername = payload['cloudProviderName'] if 'cloudProviderName' in payload else ''
    status_reason = payload['statusReason'] if 'statusReason' in payload else ''
    rf = 0

    user = dbhelpers.get_user(payload['createdBy']['subject'])
    user_email = user.email  # email

    dep = dbhelpers.get_deployment(uuid)

    if dep is not None:

        rf = dep.feedback_required
        pn = dep.provider_name if dep.provider_name is not None else ''
        if dep.status != status or dep.task != task or pn != providername or status_reason != dep.status_reason:
            if 'endpoint' in payload['outputs']:
                dep.endpoint = payload['outputs']['endpoint']
            dep.update_time = payload['updateTime']
            if 'physicalId' in payload:
                dep.physicalId = payload['physicalId']
            dep.status = status
            dep.outputs = json.dumps(payload['outputs'])
            dep.task = task
            dep.provider_name = providername
            dep.status_reason = status_reason
            dbhelpers.add_object(dep)
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    # send email to user
    mail_sender = app.config.get('MAIL_SENDER')
    if mail_sender and user_email != '' and rf == 1:
        if status == 'CREATE_COMPLETE':
            try:
                create_and_send_email("Deployment complete", mail_sender, [user_email], uuid, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'CREATE_FAILED':
            try:
                create_and_send_email("Deployment failed", mail_sender, [user_email], uuid, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'UPDATE_COMPLETE':
            try:
                create_and_send_email("Deployment update complete", mail_sender, [user_email], uuid, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'UPDATE_FAILED':
            try:
                create_and_send_email("Deployment update failed", mail_sender, [user_email], uuid, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

    resp = make_response('')
    resp.status_code = 200
    resp.mimetype = 'application/json'

    return resp


@home_bp.route('/getauthorization', methods=['POST'])
def getauthorization():

    tasks = json.loads(request.form.to_dict()["pre_tasks"].replace("'", "\""))

    functions = {'openstack.get_unscoped_keystone_token': openstack.get_unscoped_keystone_token, 'send_mail': send_authorization_request_email }

    for task in tasks["pre_tasks"]:
        func = task["action"]
        args = task["args"]
        args["access_token"] = iam_blueprint.session.token['access_token']
        if func in functions:
            functions[func](**args)

    return render_template("success_message.html", title="Message sent", message="Your request has been sent to the support team. <br>You will receive soon a notification email about your request. <br>Thank you!")


@home_bp.route('/contact', methods=['POST'])
def contact():
    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    form_data = request.form.to_dict()

    try:
        message = Markup("Name: {}<br>Email: {}<br>Message: {}".format(form_data['name'], form_data['email'], form_data['message']))
        send_email("New contact",
                   sender=app.config.get('MAIL_SENDER'),
                   recipients=[app.config.get('SUPPORT_EMAIL')],
                   html_body=message)

    except Exception as error:
        utils.logexception("sending email:".format(error))
        return Markup("<div class='alert alert-danger' role='alert'>Oops, error sending message.</div>")

    return Markup("<div class='alert alert-success' role='alert'>Your message has been sent, Thank you!</div>")


def send_authorization_request_email(service_type, **kwargs):
    message = Markup(
        "The following user has requested access for {}: <br>username: {} <br>sub: {} <br>email: {}".format(service_type, session['username'], session['userid'], session['useremail'], service_type))

    send_email("New Authorization Request",
               sender=app.config.get('MAIL_SENDER'),
               recipients = ["marica.antonacci@ba.infn.it"],
               html_body= message )

def create_and_send_email(subject, sender, recipients, uuid, status):
    send_email(subject,
               sender=sender,
               recipients=recipients,
               html_body=render_template(app.config.get('MAIL_TEMPLATE'), uuid=uuid, status=status))


def send_email(subject, sender, recipients, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    msg.body = "This email is an automatic notification" # Add plain text, needed to avoid MPART_ALT_DIFF with AntiSpam
    Thread(target=send_async_email, args=(app, msg)).start()


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)
