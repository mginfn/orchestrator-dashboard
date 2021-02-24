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
from flask import Blueprint, json, render_template, request, redirect, url_for, session, make_response, flash
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
app.jinja_env.filters['intersect'] = utils.intersect

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


def is_template_locked(allowed_groups, user_groups):
    # check intersection of user groups with user membership
    if (allowed_groups is None or set(allowed_groups.split(',')) & set(user_groups)) != set() or allowed_groups == '*':
        return False
    else:
        return True


def set_template_access(tosca, user_groups):
    info = {}
    for k, v in tosca.items():
        access_locked = is_template_locked(v.get("metadata").get("allowed_groups"), user_groups)
        if ("visibility" not in v.get("metadata") or v["metadata"]["visibility"] == "public") or not access_locked:
            v["metadata"]["access_locked"] = access_locked
            info[k] = v
    return info


def check_template_access(user_groups):
    if tosca.tosca_gmetadata:
        templates_info = set_template_access(tosca.tosca_gmetadata, user_groups)
        enable_template_groups = True
    else:
        templates_info = set_template_access(toscaInfo, user_groups)
        enable_template_groups = False
    return templates_info, enable_template_groups


@app.route('/')
@home_bp.route('/')
def home():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('home_bp.login'))

    account_info = iam_blueprint.session.get("/userinfo")

    if account_info.ok:
        account_info_json = account_info.json()
        user_groups = account_info_json['groups']
        user_id = account_info_json['sub']

        supported_groups = []
        if settings.iamGroups:
            supported_groups = list(set(settings.iamGroups) & set(user_groups))
            if len(supported_groups) == 0:
                app.logger.warning("The user {} does not belong to any supported user group".format(user_id))

        session['userid'] = user_id
        session['username'] = account_info_json['name']
        session['useremail'] = account_info_json['email']
        session['userrole'] = 'user'
        session['gravatar'] = utils.avatar(account_info_json['email'], 26)
        session['organisation_name'] = account_info_json['organisation_name']
        session['usergroups'] = user_groups
        session['supported_usergroups'] = supported_groups
        if 'active_usergroup' not in session:
            session['active_usergroup'] = next(iter(supported_groups), None)
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

            user = User(sub=user_id,
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

        # templates_info = {}
        # tg = False
        #
        # if tosca.tosca_gmetadata:
        #     templates_info = {k: v for (k, v) in tosca.tosca_gmetadata.items() if
        #              check_template_access(v.get("metadata").get("allowed_groups"), user_groups)}
        #     tg = True
        # else:
        #     templates_info = {k: v for (k, v) in toscaInfo.items() if
        #      check_template_access(v.get("metadata").get("allowed_groups"), user_groups)}
        templates_info, enable_template_groups = check_template_access(user_groups)

        return render_template(app.config.get('PORTFOLIO_TEMPLATE'), templates_info=templates_info,
                               enable_template_groups=enable_template_groups)


@home_bp.route('/set_active/<string:group>')
def set_active_usergroup(group):
    session['active_usergroup'] = group
    flash("Project switched to {}".format(group), 'info')
    return redirect(request.referrer)


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

    functions = {'openstack.get_unscoped_keystone_token': openstack.get_unscoped_keystone_token,
                 'send_mail': send_authorization_request_email}

    for task in tasks["pre_tasks"]:
        func = task["action"]
        args = task["args"]
        args["access_token"] = iam_blueprint.session.token['access_token']
        if func in functions:
            functions[func](**args)

    return render_template("success_message.html", title="Message sent",
                           message="Your request has been sent to the support team. <br>You will receive soon a notification email about your request. <br>Thank you!")


@home_bp.route('/sendaccessreq', methods=['POST'])
def sendaccessrequest():
    form_data = request.form.to_dict()

    try:
        send_authorization_request_email(form_data['service_type'], email=form_data['email'], message=form_data['message'])

        flash(
            "Your request has been sent to the support team. You will receive soon a notification email about your request. Thank you!",
            "success")

    except Exception as error:
        utils.logexception("sending email:".format(error))
        flash("Sorry, an error occurred while sending your request. Please retry.", "danger")

    return redirect(url_for('home_bp.home'))


@home_bp.route('/contact', methods=['POST'])
def contact():
    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    form_data = request.form.to_dict()

    try:
        message = Markup(
            "Name: {}<br>Email: {}<br>Message: {}".format(form_data['name'], form_data['email'], form_data['message']))
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
        "The following user has requested access for service \"{}\": <br>username: {} " \
        "<br>IAM id (sub): {} <br>IAM groups: {} <br>email registered in IAM: {} " \
        "<br>email provided by the user: {} " \
        "<br>Message: {}".format(service_type, session['username'], session['userid'],
                                 session['usergroups'], session['useremail'], kwargs['email'], kwargs['message']))

    sender = kwargs['email'] if 'email' in kwargs else session['useremail']
    send_email("New Authorization Request",
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
