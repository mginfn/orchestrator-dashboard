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
import re
from datetime import datetime

from flask import (
    Blueprint,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask import current_app as app
from markupsafe import Markup

from app.extensions import csrf, redis_client, tosca
from app.iam import iam
from app.lib import auth, dbhelpers, openstack, utils
from app.models.User import User

home_bp = Blueprint(
    "home_bp",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static/home",
)


@home_bp.route("/user")
@auth.authorized_with_valid_token
def show_user_profile():
    """
    Route for showing the user profile. Access requires a valid token.
    Retrieves the user's SSH public key from the database and renders the user profile.
    """
    sshkey = dbhelpers.get_ssh_pub_key(session["userid"])

    return render_template("user_profile.html", sshkey=sshkey)


@home_bp.route("/settings")
@auth.authorized_with_valid_token
def show_settings():
    """
    Route for displaying the settings page.
    """
    dashboard_last_conf = redis_client.get("last_configuration_info")
    last_settings = json.loads(dashboard_last_conf) if dashboard_last_conf else {}
    return render_template(
        "settings.html",
        iam_url=app.settings.iam_url,
        orchestrator_url=app.settings.orchestrator_url,
        orchestrator_conf=app.settings.orchestrator_conf,
        vault_url=app.config.get("VAULT_URL"),
        tosca_settings=last_settings,
    )


@home_bp.route("/setsettings", methods=["POST"])
@auth.authorized_with_valid_token
def submit_settings():
    """
    A function to update settings.
    It checks the user's role, then updates the current configuration
    and handles configuration reload.
    """
    if request.method == "POST" and session["userrole"].lower() == "admin":
        current_config = get_current_configuration()
        _, tosca_update_msg = update_configuration(
            current_config, "tosca_templates", app.settings.tosca_dir, "Cloning TOSCA templates"
        )
        _, conf_update_msg = update_configuration(
            current_config,
            "dashboard_configuration",
            app.settings.settings_dir,
            "Cloning dashboard configuraton",
        )

        try:
            tosca.reload()
        except Exception as error:
            handle_configuration_reload_error(error)

        handle_configuration_reload(current_config, tosca_update_msg, conf_update_msg)

    return redirect(url_for("home_bp.show_settings"))


def get_current_configuration():
    """
    Retrieve the current configuration from the redis client.

    Returns:
        dict: The current configuration information, deserialized from JSON,
        or an empty dictionary if no configuration is found.
    """
    serialised_value = redis_client.get("last_configuration_info")
    return json.loads(serialised_value) if serialised_value else {}


def update_configuration(current_config, field_prefix, repo_dir, message):
    """
    Update the configuration with the provided field prefix, repository directory, and message.

    Args:
        current_config (dict): The current configuration dictionary.
        field_prefix (str): The prefix for the fields to update in the configuration.
        repo_dir (str): The directory of the repository.
        message (str): The message to be processed.

    Returns:
        tuple: A tuple containing the result of the update (bool) and the processing message (str).
    """
    repo_url = request.form.get(f"{field_prefix}_url")
    tag_or_branch = request.form.get(f"{field_prefix}_tag_or_branch")

    private, username, deploy_token = get_repository_params(field_prefix)

    ret, message = process_repository(
        repo_dir, repo_url, tag_or_branch, private, username, deploy_token, message
    )
    if ret:
        current_config[f"{field_prefix}_url"] = repo_url
        current_config[f"{field_prefix}_tag_or_branch"] = tag_or_branch

    return ret, message


def process_repository(
    repository_dir, repo_url, tag_or_branch, private, username, deploy_token, log_message
):
    """
    Process the given repository by downloading it from the provided URL.

    :param repository_dir: The directory in which the repository will be stored
    :param repo_url: The URL of the repository to be downloaded
    :param tag_or_branch: The tag or branch of the repository to be downloaded
    :param private: Boolean indicating whether the repository is private
    :param username: The username for authentication
    :param deploy_token: The deployment token for authentication
    :param log_message: The message to be logged

    :return: A tuple containing a boolean indicating the success of the repository processing
    and a message describing the result
    """
    ret = False
    message = ""

    if repo_url:
        app.logger.debug(log_message)
        ret, message = utils.download_git_repo(
            repo_url,
            repository_dir,
            tag_or_branch,
            private,
            username,
            deploy_token,
        )
        flash(message, "success" if ret else "danger")

    return ret, message


def get_repository_params(prefix):
    """
    This function takes a prefix as a parameter and retrieves the private flag, username,
    and deploy token from the request form. It returns the private flag, username, and deploy token.
    """
    private = request.form.get(f"{prefix}_private") == "on"
    username = request.form.get(f"{prefix}_username")
    deploy_token = request.form.get(f"{prefix}_token")

    return private, username, deploy_token


def handle_configuration_reload_error(error):
    """
    Function to handle configuration reload error.

    Args:
        error: The error that occurred during configuration reload.

    Returns:
        None
    """
    app.logger.error(f"Error reloading configuration: {error}")
    flash(
        f"Error reloading configuration: { type(error).__name__ }. \
          Please check the logs.",
        "danger",
    )


def handle_configuration_reload(current_config, message1, message2):
    """
    Handles the reloading of the configuration.
    Updates the current configuration with the current timestamp,
    and notifies admins and users with the given messages.

    Args:
        current_config (dict): The current configuration settings.
        message1 (str): The first message to be sent to admins and users.
        message2 (str): The second message to be sent to admins and users.

    Returns:
        None
    """
    reload_message = "Configuration reloaded"
    flash(reload_message, "info")
    app.logger.debug(reload_message)

    now = datetime.now()
    current_config["updated_at"] = now.strftime("%d/%m/%Y %H:%M:%S")
    redis_client.set("last_configuration_info", json.dumps(current_config))

    notify_admins_and_users(message1, message2)


def notify_admins_and_users(message1, message2):
    """
    Notify admins and users about the dashboard configuration update request.

    Args:
        message1 (str): The first message for the update request.
        message2 (str): The second message for the update request.

    Returns:
        None
    """
    comment = request.form.get("message")
    message = Markup(
        "{} has requested the update of the dashboard configuration: \
                     <br><br>{} <br>{} <br><br>Comment: {}".format(
            session["username"], message1, message2, comment
        )
    )

    recipients = get_recipients()

    if recipients:
        utils.send_email(
            "Dashboard Configuration update",
            sender=app.config.get("MAIL_SENDER"),
            recipients=recipients,
            html_body=message,
        )


def get_recipients():
    """
    Get the recipients for notifications based on the request form data.
    Returns a list of email addresses.
    """
    recipients = []
    if request.form.get("notify_admins"):
        recipients = dbhelpers.get_admins_email()
    recipients.extend(request.form.getlist("notify_email"))

    return recipients


@home_bp.route("/login")
def login():
    """
    Route for handling login functionality.
    """
    session.clear()
    return render_template(app.config.get("HOME_TEMPLATE"))


def set_template_access(tosca, user_groups, active_group):
    """
    Set template access based on user groups and active group.
    """
    info = {}

    for k, v in tosca.items():
        metadata = v.get("metadata", {})
        visibility = metadata.get("visibility", {"type": "public"})

        if not active_group and visibility["type"] != "private":
            metadata["access_locked"] = True
            info[k] = v
        elif active_group:
            is_locked = is_access_locked(visibility, active_group)
            if not (visibility["type"] == "private" and is_locked):
                metadata["access_locked"] = is_locked
                info[k] = v

    return info


def is_access_locked(visibility, active_group):
    """
    Check if access is locked based on visibility and active group.

    :param visibility: dict, visibility settings
    :param active_group: str, the active group
    :return: bool, whether access is locked
    """
    regex = "groups_regex" in visibility
    if regex:
        return not re.match(visibility["groups_regex"], active_group)
    else:
        allowed_groups = visibility.get("groups", [])
        return active_group not in allowed_groups


def check_template_access(user_groups, active_group):
    """
    This function checks template access for a user within specific groups.

    Parameters:
    - user_groups: a list of user groups
    - active_group: the active group

    Returns:
    - templates_info: information about the accessible templates
    - enable_template_groups: a boolean indicating whether template groups are enabled
    """
    tosca_info, _, tosca_gmetadata = tosca.get()
    templates_data = tosca_gmetadata if tosca_gmetadata else tosca_info
    enable_template_groups = bool(tosca_gmetadata)

    templates_info = set_template_access(templates_data, user_groups, active_group)

    return templates_info, enable_template_groups


@home_bp.route("/")
def home():
    """
    A function to handle the home route, performing authorization check and redirecting accordingly.
    """
    if not iam.authorized:
        return redirect(url_for("home_bp.login"))
    if not session.get("userid"):
        auth.set_user_info()
    return redirect(url_for("home_bp.portfolio"))


@home_bp.route("/portfolio")
@auth.authorized_with_valid_token
def portfolio():
    """
    A route function for the "/portfolio" endpoint.
    Retrieves user deployments from the database and processes their statuses.
    If the user is logged in, it checks the database for the user, inserts the user if not found,
    and updates the user role, retrieves public and private services, checks template access,
    and renders the portfolio template with the retrieved data.
    If the user is not logged in, it redirects to the login page.
    """
    
    if session.get("userid"):
        # check database
        # if user not found, insert
        user = dbhelpers.get_user(session["userid"])
        if user is None:
            email = session["useremail"]
            admins = json.dumps(app.config["ADMINS"])
            role = "admin" if email in admins else "user"

            user = User(
                sub=session["userid"],
                name=session["username"],
                username=session["preferred_username"],
                given_name=session["given_name"],
                family_name=session["family_name"],
                email=email,
                organisation_name=session["organisation_name"],
                picture=utils.avatar(email, 26),
                role=role,
                active=1,
            )
            dbhelpers.add_object(user)

        session["userrole"] = user.role  # role

        services = dbhelpers.get_services(visibility="public")
        services.extend(
            dbhelpers.get_services(visibility="private", groups=[session["active_usergroup"]])
        )
        templates_info, enable_template_groups = check_template_access(
            session["usergroups"], session["active_usergroup"]
        )
        
        try:
            dbhelpers.update_deployments(session["userid"])
        except Exception as e:
            flash("Error retrieving deployment list: \n" + str(e), "warning")

        deps = dbhelpers.get_user_deployments(session["userid"])
        statuses = {}
        for dep in deps:
            status = dep.status if dep.status else "UNKNOWN"
            if status != "DELETE_COMPLETE" and dep.remote == 1:
                statuses[status] = 1 if status not in statuses else statuses[status] + 1

        return render_template(
            app.config.get("PORTFOLIO_TEMPLATE"),
            services=services,
            templates_info=templates_info,
            enable_template_groups=enable_template_groups,
            s_values=statuses,
        )
        
    return redirect(url_for("home_bp.login"))


@home_bp.route("/set_active")
def set_active_usergroup():
    """
    Route for setting the active user group.
    """
    group = request.args["group"]
    session["active_usergroup"] = group
    flash("Project switched to {}".format(group), "info")
    return redirect(request.referrer)


@home_bp.route("/logout")
def logout():
    """
    Route for logging out the user.
    """
    session.clear()
    iam.get("/logout")
    return redirect(url_for("home_bp.login"))


@home_bp.route("/callback", methods=["POST"])
@csrf.exempt
def callback():
    """
    Callback function for handling POST requests to /callback endpoint.
    Parses the JSON payload from the request, updates the deployment,
    and sends email notifications if feedback is required.
    Returns a response with status code 200 and mimetype "application/json".
    """
    payload = request.get_json()
    app.logger.info("Callback payload: " + json.dumps(payload))

    dep = update_deployment(payload)

    if dep and dep.feedback_required == 1:
        send_email_notifications(payload)

    resp = make_response("")
    resp.status_code = 200
    resp.mimetype = "application/json"

    return resp


def update_deployment(payload):
    """
    Updates a deployment using the provided payload.

    Args:
        payload (dict): The payload containing the information to update the deployment.

    Returns:
        dict: The updated deployment.
    """
    uuid = payload["uuid"]
    dep = dbhelpers.get_deployment(uuid)

    if dep is not None:
        update_deployment_attributes(dep, payload)
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    return dep


def update_deployment_attributes(dep, payload):
    """
    Updates deployment attributes based on the provided payload.

    Args:
        dep: The deployment object to be updated.
        payload: The payload containing the update information.

    Returns:
        None
    """
    status = payload["status"]
    task = payload["task"]
    uuid = payload["uuid"]
    providername = payload.get("cloudProviderName", "")
    status_reason = payload.get("statusReason", "")

    pn = dep.provider_name if dep.provider_name is not None else ""
    if (
        dep.status != status
        or dep.task != task
        or pn != providername
        or status_reason != dep.status_reason
    ):
        if "endpoint" in payload["outputs"]:
            dep.endpoint = payload["outputs"]["endpoint"]
        dep.update_time = payload["updateTime"]
        if "physicalId" in payload:
            dep.physicalId = payload["physicalId"]
        dep.status = status
        dep.outputs = json.dumps(payload["outputs"])
        dep.task = task
        dep.provider_name = providername
        dep.status_reason = status_reason
        dbhelpers.add_object(dep)
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))


def send_email_notifications(payload):
    """
    Send email notifications to the user based on the payload provided.

    Args:
    - payload: A dictionary containing information about the notification to be sent.

    Returns:
    - None
    """
    user = dbhelpers.get_user(payload["createdBy"]["subject"])
    user_email = user.email
    uuid = payload["uuid"]
    status = payload["status"]

    mail_sender = app.config.get("MAIL_SENDER")

    if mail_sender and user_email != "":
        email_subjects = {
            "CREATE_COMPLETE": "Deployment complete",
            "CREATE_FAILED": "Deployment failed",
            "UPDATE_COMPLETE": "Deployment update complete",
            "UPDATE_FAILED": "Deployment update failed",
        }
        try:
            email_subject = email_subjects.get(status, "")
            if email_subject:
                app.logger.debug(f"Prepare email with subject <{email_subject}> for <{user_email}>")
                utils.create_and_send_email(email_subject, mail_sender, [user_email], uuid, status)
        except Exception as error:
            utils.logexception("sending email: {}".format(error))


@home_bp.route("/getauthorization", methods=["POST"])
def getauthorization():
    """
    This function handles the POST request to '/getauthorization'.
    It parses the 'pre_tasks' from the request form, then iterates through the tasks
    and executes the corresponding functions from the 'functions' dictionary.
    It finally returns a rendered success message template.
    """
    tasks = json.loads(request.form.to_dict()["pre_tasks"].replace("'", '"'))

    functions = {
        "openstack.get_unscoped_keystone_token": openstack.get_unscoped_keystone_token,
        "send_mail": utils.send_authorization_request_email,
    }

    for task in tasks["pre_tasks"]:
        func = task["action"]
        args = task["args"]
        args["access_token"] = iam.token["access_token"]
        if func in functions:
            functions[func](**args)

    return render_template(
        "success_message.html",
        title="Message sent",
        message="Your request has been sent to the support team. <br>You will receive soon a notification email about your request. <br>Thank you!",
    )


@home_bp.route("/sendaccessreq", methods=["POST"])
def sendaccessrequest():
    """
    A function to handle sending an access request, which takes form data as input
    and sends an authorization request email.
    """
    form_data = request.form.to_dict()

    try:
        utils.send_authorization_request_email(
            form_data["service_type"],
            email=form_data["email"],
            message=form_data["message"],
        )

        flash(
            "Your request has been sent to the support team. You will receive soon a notification email about your "
            "request. Thank you!",
            "success",
        )

    except Exception as error:
        utils.logexception("sending email: {}".format(error))
        flash(
            "Sorry, an error occurred while sending your request. Please retry.",
            "danger",
        )

    return redirect(url_for("home_bp.home"))


@home_bp.route("/contact", methods=["POST"])
def contact():
    """
    A route for handling contact form submission via POST method.
    """
    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    form_data = request.form.to_dict()

    try:
        message = Markup(
            "Name: {}<br>Email: {}<br>Message: {}".format(
                form_data["name"], form_data["email"], form_data["message"]
            )
        )
        utils.send_email(
            "New contact",
            sender=app.config.get("MAIL_SENDER"),
            recipients=[app.config.get("SUPPORT_EMAIL")],
            html_body=message,
        )

    except Exception as error:
        utils.logexception("sending email: {}".format(error))
        return Markup(
            "<div class='alert alert-danger' role='alert'>Oops, error sending message.</div>"
        )

    return Markup(
        "<div class='alert alert-success' role='alert'>Your message has been sent, Thank you!</div>"
    )
