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

import copy
import io
import os
import random
import string
from typing import Optional
import uuid as uuid_generator
from re import search
from urllib.parse import urlparse

import openstack
import openstack.connection
import yaml
from flask import (
    Blueprint,
    flash,
    json,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask import current_app as app
from werkzeug.exceptions import Forbidden

from app.extensions import tosca, vaultservice
from app.iam import iam
from app.lib import auth, dbhelpers, fed_reg, s3, utils
from app.lib import openstack as keystone
from app.lib import tosca_info as tosca_helpers
from app.lib.ldap_user import LdapUserManager
from app.models.Deployment import Deployment
from app.providers import sla

# Initialize and turn on debug logging
openstack.enable_logging(debug=True)


deployments_bp = Blueprint(
    "deployments_bp", __name__, template_folder="templates", static_folder="static"
)

SHOW_DEPLOYMENTS_ROUTE = "deployments_bp.showdeployments"
MANAGE_RULES_ROUTE = "deployments_bp.manage_rules"


class InputValidationError(Exception):
    """Exception raised for errors in the input validation process."""

    pass


@deployments_bp.route("/depls")
@auth.authorized_with_valid_token
def showdeploymentsingroup():
    group = request.args["group"]
    session["active_usergroup"] = group
    flash("Project set to {}".format(group), "info")
    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/list")
@auth.authorized_with_valid_token
def showdeployments():
    access_token = iam.token["access_token"]

    group = None
    if "active_usergroup" in session and session["active_usergroup"] is not None:
        group = session["active_usergroup"]

    deployments = []
    try:
        deployments = app.orchestrator.get_deployments(
            access_token, created_by="me", user_group=group
        )
    except Exception as e:
        flash("Error retrieving deployment list: \n" + str(e), "warning")

    if deployments:
        result = dbhelpers.updatedeploymentsstatus(deployments, session["userid"])
        deployments = result["deployments"]
        app.logger.debug("Deployments: " + str(deployments))

        deployments_uuid_array = result["iids"]
        session["deployments_uuid_array"] = deployments_uuid_array

    return render_template("deployments.html", deployments=deployments)


@deployments_bp.route("/overview")
@auth.authorized_with_valid_token
def showdeploymentsoverview():
    # refresh deployment list
    try:
        dbhelpers.update_deployments(session["userid"])
    except Exception as e:
        flash("Error retrieving deployment list: \n" + str(e), "warning")

    deps = dbhelpers.get_user_deployments(session["userid"])
    # Initialize dictionaries for status, projects, and providers
    statuses = {"UNKNOWN": 0}
    projects = {"UNKNOWN": 0}
    providers = {"UNKNOWN": 0}

    for dep in deps:
        status = dep.status or "UNKNOWN"
        if status != "DELETE_COMPLETE" and dep.remote == 1:
            statuses[status] = statuses.get(status, 0) + 1

            project = dep.user_group or "UNKNOWN"
            projects[project] = projects.get(project, 0) + 1

            provider = dep.provider_name or "UNKNOWN"
            providers[provider] = providers.get(provider, 0) + 1

    return render_template(
        "depoverview.html",
        s_title="Deployments status",
        s_labels=list(statuses.keys()),
        s_values=list(statuses.values()),
        s_colors=utils.genstatuscolors(statuses),
        p_title="Projects",
        p_labels=list(projects.keys()),
        p_values=list(projects.values()),
        p_colors=utils.gencolors("blue", len(projects)),
        pr_title="Providers",
        pr_labels=list(providers.keys()),
        pr_values=list(providers.values()),
        pr_colors=utils.gencolors("green", len(providers)),
    )


@deployments_bp.route("/<depid>/template")
@auth.authorized_with_valid_token
def deptemplate(depid=None):
    access_token = iam.token["access_token"]

    try:
        template = app.orchestrator.get_template(access_token, depid)
    except Exception:
        flash("Error getting template: ".format(), "danger")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    return render_template("deptemplate.html", template=template)


@deployments_bp.route("/<depid>/lock")
@auth.authorized_with_valid_token
def lockdeployment(depid=None):
    dep = dbhelpers.get_deployment(depid)
    if dep is not None:
        dep.locked = 1
        dbhelpers.add_object(dep)
    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/<depid>/unlock")
@auth.authorized_with_valid_token
def unlockdeployment(depid=None):
    dep = dbhelpers.get_deployment(depid)
    if dep is not None:
        dep.locked = 0
        dbhelpers.add_object(dep)
    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/edit", methods=["POST"])
@auth.authorized_with_valid_token
def editdeployment():
    form_data = request.form.to_dict()
    dbhelpers.update_deployment(
        form_data["deployment_uuid"], dict(description=form_data["description"])
    )
    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


def preprocess_outputs(outputs, stoutputs, inputs):
    """
    Preprocesses the outputs based on the given inputs and stoutputs.

    :param outputs: The outputs to be preprocessed.
    :param stoutputs: The stoutputs containing conditions for preprocessing.
    :param inputs: The inputs used to evaluate the output conditions.
    """
    # note: inputs parameter is made available in this function
    # for evaluating output conditions (see below)

    for key, value in stoutputs.items():
        if "condition" in value:
            try:
                if not eval(value.get("condition")) and key in outputs:
                    del outputs[key]
            except InputValidationError as ex:
                app.logger.warning("Error evaluating condition for output {}: {}".format(key, ex))


@deployments_bp.route("/<depid>/details")
@auth.authorized_with_valid_token
def depoutput(depid=None):
    """
    A function to render the details of a deployment, including inputs, outputs,
    and structured outputs.
    Parameters:
    - depid: str, the ID of the deployment
    Returns:
    - rendered template with deployment details, inputs, outputs, and structured outputs
    """
    if session["userrole"].lower() != "admin" and depid not in session["deployments_uuid_array"]:
        flash("You are not allowed to browse this page!", "danger")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    inputs, outputs, stoutputs = process_deployment_data(dep)

    return render_template(
        "depoutput.html",
        deployment=dep,
        inputs=inputs,
        outputs=outputs,
        stoutputs=stoutputs,
    )


def is_input_printable(stinputs, k):
    """
    Check if the input is printable
    Args:
        stinputs: The input dictionary.
        k: The key to check in the input dictionary.
    Returns:
        A boolean indicating whether the input is printable
        or True if the key is not in the input dictionary.
    """
    return stinputs.get(k, {}).get("printable", True) if k in stinputs else True


def process_deployment_data(dep):
    """
    Process deployment data and return inputs, outputs, and stoutputs.

    Parameters:
    dep: The deployment data to process.

    Returns:
    inputs: The processed inputs.
    outputs: The processed outputs.
    stoutputs: The processed stoutputs.
    """
    i = json.loads(dep.inputs.strip('"')) if dep.inputs else {}
    stinputs = json.loads(dep.stinputs.strip('"')) if dep.stinputs else {}
    outputs = json.loads(dep.outputs.strip('"')) if dep.outputs else {}
    stoutputs = json.loads(dep.stoutputs.strip('"')) if dep.stoutputs else {}

    inputs = {k: v for k, v in i.items() if is_input_printable(stinputs, k)}

    preprocess_outputs(outputs, stoutputs, inputs)

    return inputs, outputs, stoutputs


@deployments_bp.route("/<depid>/templatedb")
def deptemplatedb(depid):
    if not iam.authorized:
        return redirect(url_for("home_bp.login"))
    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))
    else:
        template = dep.template
        return render_template("deptemplate.html", template=template)


@deployments_bp.route("/<depid>/log")
@auth.authorized_with_valid_token
def deplog(depid=None):
    access_token = iam.token["access_token"]
    dep = dbhelpers.get_deployment(depid)

    log = "Not available"
    if dep is not None:
        try:
            log = app.orchestrator.get_log(access_token, depid)
        except Exception:
            pass
    return render_template("deplog.html", log=log)


def extract_vm_details(depid, resources):
    details = []
    for resource in resources:
        if "VirtualMachineInfo" in resource["metadata"]:
            vminfo = json.loads(resource["metadata"]["VirtualMachineInfo"])
            vmprop = utils.format_json_radl(vminfo["vmProperties"])
            vmprop["state"] = resource["state"]
            vmprop["resId"] = resource["uuid"]
            vmprop["depId"] = depid
            details.append(vmprop)
    return details


def process_tosca_info(dep):
    template = dep.template
    tosca_info = tosca.extracttoscainfo(yaml.full_load(io.StringIO(template)), None)
    inputs = json.loads(dep.inputs.strip('"')) if dep.inputs else {}
    stinputs = json.loads(dep.stinputs.strip('"')) if dep.stinputs else {}
    tosca_info["inputs"] = {**tosca_info["inputs"], **stinputs}

    for k, v in tosca_info["inputs"].items():
        if k in inputs and "default" in tosca_info["inputs"][k]:
            tosca_info["inputs"][k]["default"] = inputs[k]

    stoutputs = json.loads(dep.stoutputs.strip('"')) if dep.stoutputs else {}
    tosca_info["outputs"] = {**tosca_info["outputs"], **stoutputs}
    return tosca_info


@deployments_bp.route("/<depid>/infradetails")
@auth.authorized_with_valid_token
def depinfradetails(depid=None):
    access_token = iam.token["access_token"]

    dep = dbhelpers.get_deployment(depid)

    if dep is None or dep.physicalId is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    try:
        resources = app.orchestrator.get_resources(access_token, depid)
    except Exception as e:
        flash(str(e), "warning")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    details = extract_vm_details(depid, resources)
    tosca_info = process_tosca_info(dep)

    return render_template(
        "depinfradetails.html",
        vmsdetails=details,
        deployment=dep,
        template=tosca_info,
        update=True,
    )


# PORTS MANAGEMENT
def get_openstack_connection(
    *,
    endpoint: str,
    provider_name: str,
    provider_type: Optional[str] = None,
    region_name: Optional[str] = None,
) -> openstack.connection.Connection:
    """Create openstack connection, to target project, using access token."""
    conn = None

    # Fed-Reg
    if app.settings.fed_reg_url is not None:
        # Find target provider
        providers = fed_reg.get_providers(
            access_token=iam.token["access_token"],
            with_conn=True,
            name=provider_name,
            type=provider_type,
        )
        assert (
            len(providers) < 2
        ), f"Found multiple providers with name '{provider_name}' and type '{provider_type}'"
        assert (
            len(providers) > 0
        ), f"Provider with name '{provider_name}' and type '{provider_type}' not found"
        provider = providers[0]

        # Retrieve the authentication details matching the current identity provider
        identity_provider = next(
            filter(
                lambda x: x["endpoint"] == session["iss"],
                provider["identity_providers"],
            )
        )
        auth_method = identity_provider["relationship"]

        # Retrieve the auth_url matching the target region. In older deployments,
        # if not inferred from the provider name, the region is None.
        if region_name is not None:
            region = next(
                filter(lambda x: x["name"] == region_name, provider["regions"])
            )
        else:
            region = provider["regions"][0]
        identity_service = next(
            filter(lambda x: x["type"] == "identity", region["services"])
        )

        # Retrieve user groups to get target project
        user_group = next(
            filter(
                lambda x: x["name"] == session["active_usergroup"],
                identity_provider["user_groups"],
            )
        )
        projects = fed_reg.get_projects(
            access_token=iam.token["access_token"],
            with_conn=True,
            provider_uid=provider["uid"],
            user_group_uid=user_group["uid"],
        )
        assert len(projects) < 2, "Found multiple projects"
        assert len(projects) > 0, "Projects not found"
        project = projects[0]

        # Create openstack connection
        conn = openstack.connect(
            auth=dict(
                auth_url=identity_service["endpoint"],
                project_id=project["uuid"],
                protocol=auth_method["protocol"],
                identity_provider=auth_method["idp_name"],
                access_token=iam.token["access_token"],
            ),
            region_name=region_name,
            identity_api_version=3,
            auth_type="v3oidcaccesstoken",
        )
    # SLAM
    elif app.settings.orchestrator_conf.get("slam_url", None) is not None:
        service = app.cmdb.get_service_by_endpoint(
            iam.token["access_token"], endpoint, provider_name, False
        )

        prj, idp = app.cmdb.get_service_project(
            iam.token["access_token"],
            session["iss"],
            service,
            session["active_usergroup"],
        )

        if not prj or not idp:
            raise Exception("Unable to get service/project information.")

        conn = openstack.connect(
            auth=dict(
                auth_url=service["endpoint"],
                project_id=prj.get("tenant_id"),
                protocol=idp["protocol"],
                identity_provider=idp["name"],
                access_token=iam.token["access_token"],
            ),
            region_name=service["region"],
            identity_api_version=3,
            auth_type="v3oidcaccesstoken",
        )

    return conn


def get_vm_info(depid):
    dep = dbhelpers.get_deployment(depid)
    if dep is None or dep.physicalId is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    try:
        resources = app.orchestrator.get_resources(iam.token["access_token"], depid)
    except Exception as e:
        flash(str(e), "warning")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    def find_node_with_pubip(resources):
        for resource in resources:
            if "VirtualMachineInfo" in resource["metadata"]:
                vm_info = json.loads(resource["metadata"]["VirtualMachineInfo"])["vmProperties"]
                networks = [i for i in vm_info if i.get("class") == "network"]
                vmi = next(i for i in vm_info if i.get("class") == "system")

                for network in networks:
                    if network.get("id") == "pub_network":
                        return vmi.get("instance_id"), vmi.get("provider.host")
        return "", ""

    vm_id, vm_endpoint = find_node_with_pubip(resources)
    return {
        "vm_id": vm_id,
        "vm_endpoint": vm_endpoint,
        "vm_provider_type": dep.provider_type,
        "vm_region": dep.region_name,
    }


def get_sec_groups(conn, server_id, public=True):
    substring = "pub_network"
    sec_group_list = conn.list_server_security_groups(server_id)
    return_sec_group_list = []

    # remove duplicates
    for sec_group in sec_group_list:
        flag = True

        for return_sec_group in return_sec_group_list:
            if return_sec_group["id"] == sec_group["id"]:
                flag = False

        if flag:
            return_sec_group_list.append(sec_group)

    if public:
        return_sec_group_list = [
            sec_group for sec_group in return_sec_group_list if search(substring, sec_group["name"])
        ]

    return return_sec_group_list


@deployments_bp.route("/<depid>/security_groups")
@auth.authorized_with_valid_token
def security_groups(depid=None):
    try:
        sec_groups = ""

        vm_provider = request.args.get("depProvider")
        vm_info = get_vm_info(depid)
        vm_id = vm_info["vm_id"]
        vm_endpoint = vm_info["vm_endpoint"]

        conn = get_openstack_connection(
            endpoint=vm_endpoint,
            provider_name=vm_provider,
            provider_type=vm_info["vm_provider_type"],
            region_name=vm_info["vm_region"],
        )
        sec_groups = get_sec_groups(conn, vm_id)

        if len(sec_groups) == 1:
            return redirect(
                url_for(
                    MANAGE_RULES_ROUTE,
                    depid=depid,
                    provider=vm_provider,
                    sec_group_id=sec_groups[0]["id"],
                )
            )

        return render_template("depsecgroups.html", depid=depid, sec_groups=sec_groups)
    except Exception as e:
        flash(str(e), "warning")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/<depid>/<sec_group_id>/manage_rules")
@auth.authorized_with_valid_token
def manage_rules(depid=None, sec_group_id=None):
    provider = request.args.get("provider")

    vm_info = get_vm_info(depid)
    conn = get_openstack_connection(
        endpoint=vm_info["vm_endpoint"],
        provider_name=provider,
        provider_type=vm_info["vm_provider_type"],
        region_name=vm_info["vm_region"],
    )

    rules = conn.list_security_groups({"id": sec_group_id})

    if len(rules) != 0:
        rules = rules[0].security_group_rules
    else:
        rules = []

    return render_template(
        "depgrouprules.html", depid=depid, provider=provider, sec_group_id=sec_group_id, rules=rules
    )


@deployments_bp.route("/<depid>/<sec_group_id>/create_rule", methods=["POST"])
@auth.authorized_with_valid_token
def create_rule(depid=None, sec_group_id=None):
    provider = request.args.get("provider")
    vm_info = get_vm_info(depid)
    try:
        conn = get_openstack_connection(
            endpoint=vm_info["vm_endpoint"],
            provider_name=provider,
            provider_type=vm_info["vm_provider_type"],
            region_name=vm_info["vm_region"],
        )
        conn.network.create_security_group_rule(
            security_group_id=sec_group_id,
            description=request.form["input_description"],
            direction=request.form["input_direction"]
            if request.form["input_direction"] != ""
            else None,
            ethertype="IPv4",
            port_range_min=request.form["input_port_from"]
            if request.form["input_port_from"] != ""
            else None,
            port_range_max=request.form["input_port_to"]
            if request.form["input_port_to"] != ""
            else None,
            protocol=request.form["input_ip_protocol"]
            if request.form["input_ip_protocol"] != ""
            else "tcp",
            remote_ip_prefix=request.form["input_CIDR"]
            if request.form["input_CIDR"] != ""
            else None,
        )
        flash("Port created successfully!", "success")
    except Exception as e:
        flash("Error: \n" + str(e), "danger")

    return redirect(
        url_for(MANAGE_RULES_ROUTE, depid=depid, provider=provider, sec_group_id=sec_group_id)
    )


@deployments_bp.route("/<depid>/<sec_group_id>/<rule_id>/delete_rule")
@auth.authorized_with_valid_token
def delete_rule(depid=None, sec_group_id=None, rule_id=None):
    provider = request.args.get("provider")
    vm_info = get_vm_info(depid)
    try:
        conn = get_openstack_connection(
            endpoint=vm_info["vm_endpoint"],
            provider_name=provider,
            provider_type=vm_info["vm_provider_type"],
            region_name=vm_info["vm_region"],
        )
        conn.delete_security_group_rule(rule_id)
        flash("Port deleted successfully!", "success")
    except Exception as e:
        flash("Error: \n" + str(e), "danger")

    return redirect(
        url_for(MANAGE_RULES_ROUTE, depid=depid, provider=provider, sec_group_id=sec_group_id)
    )


# ---


@deployments_bp.route("/<depid>/actions", methods=["POST"])
@auth.authorized_with_valid_token
def depaction(depid):
    access_token = iam.token["access_token"]
    dep = dbhelpers.get_deployment(depid)
    if dep is not None and dep.physicalId is not None:
        try:
            app.logger.debug(f"Requested action on deployment {dep.uuid}")
            app.orchestrator.post_action(
                access_token, depid, request.args["vmid"], request.args["action"]
            )
            flash("Action successfully triggered.", "success")
        except Exception as e:
            app.logger.error("Action on deployment {} failed: {}".format(dep.uuid, str(e)))
            flash(str(e), "warning")

    return redirect(url_for("deployments_bp.depinfradetails", depid=depid))


@deployments_bp.route("/<depid>/delnode", methods=["POST"])
@auth.authorized_with_valid_token
def delnode(depid):
    access_token = iam.token["access_token"]
    dep = dbhelpers.get_deployment(depid)
    if dep is not None and dep.physicalId is not None:
        try:
            vm_id = request.args["vmid"]
            app.logger.debug(f"Requested deletion of node {vm_id} on deployment {dep.uuid}")
            resource = app.orchestrator.get_resource(access_token, depid, vm_id)
            resources = app.orchestrator.get_resources(access_token, depid)

            node = next((res for res in resources if res.get("uuid") == vm_id), None)
            node_name = node.get("toscaNodeName")
            # current count -1 --> remove one node
            count = sum(1 for res in resources if res.get("toscaNodeName") == node_name) - 1

            app.logger.debug(f"Resource details: {resource}")
            app.logger.debug(f"Count = {count}")

            template = app.orchestrator.get_template(access_token, depid)

            template_dict = yaml.full_load(io.StringIO(template))

            new_template, new_inputs = tosca_helpers.set_removal_list(
                template_dict, node_name, [vm_id], count
            )

            template_text = yaml.dump(new_template, default_flow_style=False, sort_keys=False)
            app.logger.debug(f"{template_text}")

            app.orchestrator.update(
                access_token,
                depid,
                template_text,
                new_inputs,
                dep.keep_last_attempt,
                app.config["PROVIDER_TIMEOUT"],
                app.config["OVERALL_TIMEOUT"],
                app.config["CALLBACK_URL"],
            )
            # update inputs for deployment stored in the DB
            oldinputs = json.loads(dep.inputs.strip('"')) if dep.inputs else {}
            updatedinputs = {**oldinputs, **new_inputs}
            dep.inputs = (json.dumps(updatedinputs),)
            dbhelpers.add_object(dep)

            flash("Node deletion successfully triggered.", "success")
        except Exception as e:
            err_msg = f"Node deletion on deployment {dep.uuid} failed: {str(e)}"
            app.logger.error(err_msg)
            flash(err_msg, "warning")

    return redirect(url_for("deployments_bp.depinfradetails", depid=depid))


@deployments_bp.route("/<depid>/qcgdetails")
@auth.authorized_with_valid_token
def depqcgdetails(depid=None):
    access_token = iam.token["access_token"]

    dep = dbhelpers.get_deployment(depid)
    if dep is not None and dep.physicalId is not None and dep.deployment_type == "QCG":
        try:
            job = json.loads(app.orchestrator.get_extra_info(access_token, depid))
        except Exception as e:
            app.logger.warning("Error decoding Job details response: {}".format(str(e)))
            job = None

        return render_template("depqcgdetails.html", job=(job[0] if job else None))
    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/<depid>/delete")
@auth.authorized_with_valid_token
def depdel(depid=None):
    access_token = iam.token["access_token"]

    dep = dbhelpers.get_deployment(depid)
    if dep is not None and dep.storage_encryption == 1:
        secret_path = session["userid"] + "/" + dep.vault_secret_uuid
        delete_secret_from_vault(access_token, secret_path)

    try:
        app.orchestrator.delete(access_token, depid)
    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/depupdate/<depid>")
@auth.authorized_with_valid_token
def depupdate(depid=None):
    if depid is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    dep = dbhelpers.get_deployment(depid)

    if dep is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    access_token = iam.token["access_token"]
    template = dep.template
    tosca_info = tosca.extracttoscainfo(yaml.full_load(io.StringIO(template)), None)
    inputs = json.loads(dep.inputs.strip('"')) if dep.inputs else {}
    stinputs = json.loads(dep.stinputs.strip('"')) if dep.stinputs else {}
    tosca_info["inputs"] = {**tosca_info["inputs"], **stinputs}

    for k, v in tosca_info["inputs"].items():
        if k in inputs and "default" in tosca_info["inputs"][k]:
            tosca_info["inputs"][k]["default"] = inputs[k]

    stoutputs = json.loads(dep.stoutputs.strip('"')) if dep.stoutputs else {}
    tosca_info["outputs"] = {**tosca_info["outputs"], **stoutputs}

    sla_id = tosca_helpers.getslapolicy(tosca_info)

    slas = []
    # Fed-Reg
    app.logger.debug("FED_REG_URL: {}".format(app.settings.fed_reg_url))
    if app.settings.fed_reg_url is not None:
        slas = fed_reg.retrieve_slas_from_specific_user_group(
            access_token=access_token,
            service_type="compute",
            deployment_type=dep.deployment_type,
        )

    # SLAM
    elif app.settings.orchestrator_conf.get("slam_url", None) is not None:
        slas = sla.get_slas(
            access_token,
            app.settings.orchestrator_conf["slam_url"],
            app.settings.orchestrator_conf["cmdb_url"],
            dep.deployment_type,
        )

    ssh_pub_key = dbhelpers.get_ssh_pub_key(session["userid"])

    return render_template(
        "updatedep.html",
        template=tosca_info,
        template_description=tosca_info["description"],
        instance_description=dep.description,
        feedback_required=dep.feedback_required,
        keep_last_attempt=dep.keep_last_attempt,
        provider_timeout=app.config["PROVIDER_TIMEOUT"],
        selectedTemplate=dep.selected_template,
        ssh_pub_key=ssh_pub_key,
        slas=slas,
        sla_id=sla_id,
        depid=depid,
        update=True,
    )


@deployments_bp.route("/addnodes/<depid>", methods=["POST"])
@auth.authorized_with_valid_token
def addnodes(depid):
    access_token = iam.token["access_token"]

    form_data = request.form.to_dict()

    app.logger.debug(f"Form data for dep {depid}: {json.dumps(form_data)}")

    dep = dbhelpers.get_deployment(depid)

    if dep is None or dep.physicalId is None:
        flash("Deployment not found or invalid.", "warning")
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    try:
        template = app.orchestrator.get_template(access_token, depid)

        template_dict = yaml.full_load(io.StringIO(template))

        template_text = yaml.dump(template_dict, default_flow_style=False, sort_keys=False)

        new_inputs = extract_inputs(form_data)

        old_inputs = json.loads(dep.inputs.strip('"')) if dep.inputs else {}

        # do not trigger an update if nothing changes
        if not form_data.get("extra_opts.force_update") and all(
            old_inputs.get(k) == v for k, v in new_inputs.items()
        ):
            message = f"Node addition Aborted for Deployment {dep.uuid}: No changes detected"
            app.logger.error(message)
            flash(message, "warning")
            return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

        app.orchestrator.update(
            access_token,
            depid,
            template_text,
            new_inputs,
            dep.keep_last_attempt,
            app.config["PROVIDER_TIMEOUT"],
            app.config["OVERALL_TIMEOUT"],
            app.config["CALLBACK_URL"],
        )
        # update inputs for deployment stored in the DB
        updatedinputs = {**old_inputs, **new_inputs}
        dep.inputs = (json.dumps(updatedinputs),)
        dbhelpers.add_object(dep)
        flash("Node addition successfully triggered.", "success")
    except Exception as e:
        err_msg = f"Node addition on deployment {dep.uuid} failed: {str(e)}"
        app.logger.error(err_msg)
        flash(err_msg, "warning")

    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/updatedep", methods=["POST"])
@auth.authorized_with_valid_token
def updatedep():
    access_token = iam.token["access_token"]

    form_data = request.form.to_dict()

    app.logger.debug("Form data: " + json.dumps(form_data))

    depid = form_data["_depid"]

    if depid is None:
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    dep = dbhelpers.get_deployment(depid)

    template = yaml.full_load(io.StringIO(dep.template))

    if form_data["extra_opts.schedtype"].lower() == "man":
        template = add_sla_to_template(template, form_data["extra_opts.selectedSLA"])
    else:
        remove_sla_from_template(template)
    app.logger.debug(yaml.dump(template, default_flow_style=False))

    stinputs = json.loads(dep.stinputs.strip('"')) if dep.stinputs else {}
    inputs = {
        k: v
        for (k, v) in form_data.items()
        if not k.startswith("extra_opts.")
        and k != "_depid"
        and (k in stinputs and "updatable" in stinputs[k] and stinputs[k]["updatable"] is True)
    }

    app.logger.debug("Parameters: " + json.dumps(inputs))

    template_text = yaml.dump(template, default_flow_style=False, sort_keys=False)

    app.logger.debug("[Deployment Update] inputs: {}".format(json.dumps(inputs)))
    app.logger.debug("[Deployment Update] Template: {}".format(template_text))

    keep_last_attempt = 1 if "extra_opts.keepLastAttempt" in form_data else dep.keep_last_attempt
    feedback_required = 1 if "extra_opts.sendEmailFeedback" in form_data else dep.feedback_required
    provider_timeout_mins = (
        form_data["extra_opts.providerTimeout"]
        if "extra_opts.providerTimeoutSet" in form_data
        else app.config["PROVIDER_TIMEOUT"]
    )

    try:
        app.orchestrator.update(
            access_token,
            depid,
            template_text,
            inputs,
            keep_last_attempt,
            provider_timeout_mins,
            app.config["OVERALL_TIMEOUT"],
            app.config["CALLBACK_URL"],
        )
        # store data into database
        dep.keep_last_attempt = keep_last_attempt
        dep.feedback_required = feedback_required
        dep.template = template_text
        oldinputs = json.loads(dep.inputs.strip('"')) if dep.inputs else {}
        updatedinputs = {**oldinputs, **inputs}
        dep.inputs = (json.dumps(updatedinputs),)
        dbhelpers.add_object(dep)

    except Exception as e:
        flash(str(e), "danger")

    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


@deployments_bp.route("/configure", methods=["GET"])
@auth.authorized_with_valid_token
def configure():
    steps = {"current": 1, "total": 2}
    tosca_info, _, tosca_gmetadata = tosca.get()

    selected_tosca = None

    if "selected_tosca" in request.args:
        selected_tosca = request.args["selected_tosca"]

    if "selected_group" in request.args:
        templates = tosca_gmetadata[request.args["selected_group"]]["templates"]

        if len(templates) == 1:
            selected_tosca = templates[0]["name"]
        else:
            return render_template("choosedep.html", templates=templates)

    return prepare_configure_form(selected_tosca, tosca_info, steps)


@deployments_bp.route("/configure", methods=["POST"])
@auth.authorized_with_valid_token
def configure_post():
    check_data = 0
    steps = {"current": 1, "total": 2}

    tosca_info, _, _ = tosca.get()

    selected_tosca = None

    selected_tosca = request.form.get("selected_tosca")

    if "check_data" in request.args:
        check_data = int(request.args["check_data"])

    if check_data == 1:  # from choose
        steps["total"] = 3
        steps["current"] = 2

    return prepare_configure_form(selected_tosca, tosca_info, steps)


def prepare_configure_form(selected_tosca, tosca_info, steps):
    access_token = iam.token["access_token"]
    if selected_tosca:
        template = copy.deepcopy(tosca_info[selected_tosca])
        # Manage eventual overrides
        for k, v in list(template["inputs"].items()):
            if "group_overrides" in v and session["active_usergroup"] in v["group_overrides"]:
                overrides = v["group_overrides"][session["active_usergroup"]]
                template["inputs"][k] = {**v, **overrides}
                del template["inputs"][k]["group_overrides"]

        sla_id = tosca_helpers.getslapolicy(template)

        slas = []
        # Fed-Reg
        app.logger.debug("FED_REG_URL: {}".format(app.settings.fed_reg_url))
        if app.settings.fed_reg_url is not None:
            slas = fed_reg.retrieve_slas_from_specific_user_group(
                access_token=access_token,
                service_type="compute",
                deployment_type=template["deployment_type"],
            )

        # SLAM
        elif app.settings.orchestrator_conf.get("slam_url", None) is not None:
            slas = sla.get_slas(
                access_token,
                app.settings.orchestrator_conf["slam_url"],
                app.settings.orchestrator_conf["cmdb_url"],
                template["deployment_type"],
            )

        ssh_pub_key = dbhelpers.get_ssh_pub_key(session["userid"])

        if not ssh_pub_key and app.config.get("FEATURE_REQUIRE_USER_SSH_PUBKEY") == "yes":
            flash(
                "Warning! You will not be able to deploy your service \
                    as no Public SSH key has been uploaded.",
                "danger",
            )

        return render_template(
            "createdep.html",
            template=template,
            template_inputs=json.dumps(template["inputs"], ensure_ascii=False),
            feedback_required=True,
            keep_last_attempt=False,
            provider_timeout=app.config["PROVIDER_TIMEOUT"],
            selectedTemplate=selected_tosca,
            ssh_pub_key=ssh_pub_key,
            slas=slas,
            steps=steps,
            sla_id=sla_id,
            update=False,
        )


def remove_sla_from_template(template):
    if "policies" in template["topology_template"]:
        for policy in template["topology_template"]["policies"]:
            for k, v in policy.items():
                if "type" in v and (
                    v["type"] == "tosca.policies.indigo.SlaPlacement"
                    or v["type"] == "tosca.policies.Placement"
                ):
                    template["topology_template"]["policies"].remove(policy)
                    break
        if len(template["topology_template"]["policies"]) == 0:
            del template["topology_template"]["policies"]


def add_sla_to_template(template, sla_id):
    # Add or replace the placement policy

    tosca_sla_placement_type = "tosca.policies.indigo.SlaPlacement"
    template["topology_template"]["policies"] = [
        {
            "deploy_on_specific_site": {
                "type": tosca_sla_placement_type,
                "properties": {"sla_id": sla_id},
            }
        }
    ]

    return template


def extract_inputs(form_data):
    return {
        k: v
        for (k, v) in form_data.items()
        if not k.startswith("extra_opts.") and k != "csrf_token"
    }


def load_template(selected_template):
    with io.open(
        os.path.join(app.settings.tosca_dir, selected_template), encoding="utf-8"
    ) as stream:
        template = yaml.full_load(stream)
        stream.seek(0)
        template_text = stream.read()
    return template, template_text


def process_dependent_definition(key: str, inputs: dict, stinputs: dict):
    value = stinputs[key]
    if value["type"] == "dependent_definition":
        # retrieve the real type from dedicated field
        if inputs[key + "-ref"] in stinputs:
            stinputs[key] = stinputs[inputs[key + "-ref"]]
        del inputs[key + "-ref"]


def process_security_groups(key: str, inputs: dict, stinputs: dict, form_data: dict):
    value = stinputs.get(key)

    if not value or value["type"] != "map":
        return

    port_types = ["tosca.datatypes.network.PortSpec", "tosca.datatypes.indigo.network.PortSpec"]
    if not any(value["entry_schema"]["type"] == t for t in port_types):
        return

    if key in inputs:
        process_inputs_for_security_groups(key, value, inputs, form_data)


def process_inputs_for_security_groups(key, value, inputs, form_data):
    try:
        inputs[key] = json.loads(form_data.get(key, {}))
        for k, v in inputs[key].items():
            if "," in v["source"]:
                v["source_range"] = json.loads(v.pop("source", None))
    except Exception:
        del inputs[key]
        inputs[key] = {"ssh": {"protocol": "tcp", "source": 22}}

    if "required_ports" in value:
        inputs[key] = {**value["required_ports"], **inputs[key]}


def process_map(key: str, inputs: dict, stinputs: dict, form_data: dict):
    value = stinputs[key]
    if value["type"] == "map" and value["entry_schema"]["type"] == "string":
        if key in inputs:
            try:
                inputs[key] = {}
                imap = json.loads(form_data[key])
                for k, v in imap.items():
                    inputs[key][v["key"]] = v["value"]
            except Exception:
                del inputs[key]


def process_list(key: str, inputs: dict, stinputs: dict, form_data: dict):
    value = stinputs[key]

    if value["type"] == "list" and key in inputs:
        try:
            json_data = json.loads(form_data[key])
            if (
                value["entry_schema"]["type"] == "map"
                and value["entry_schema"]["entry_schema"]["type"] == "string"
            ):
                array = []
                for el in json_data:
                    array.append({el["key"]: el["value"]})
                inputs[key] = array
            else:
                inputs[key] = json_data
        except Exception:
            del inputs[key]


def process_ssh_user(key: str, inputs: dict, stinputs: dict):
    value = stinputs[key]
    if value["type"] == "ssh_user":
        app.logger.info("Add ssh user")
        if app.config.get("FEATURE_REQUIRE_USER_SSH_PUBKEY") == "yes":
            if dbhelpers.get_ssh_pub_key(session["userid"]):
                inputs[key] = [
                    {
                        "os_user_name": session["preferred_username"],
                        "os_user_add_to_sudoers": True,
                        "os_user_ssh_public_key": dbhelpers.get_ssh_pub_key(session["userid"]),
                    }
                ]
            else:
                flash(
                    "Deployment request failed: no SSH key found. Please upload your key.",
                    "danger",
                )
                raise InputValidationError(
                    "Deployment request failed: no SSH key found. Please upload your key."
                )


def process_random_password(key: str, inputs: dict, stinputs: dict):
    value = stinputs[key]
    if value["type"] == "random_password":
        inputs[key] = utils.generate_password()


def process_uuidgen(key: str, inputs: dict, stinputs: dict, uuidgen_deployment: str):
    value = stinputs[key]
    if value["type"] == "uuidgen":
        prefix = ""
        suffix = ""
        if "extra_specs" in value:
            prefix = value["extra_specs"]["prefix"] if "prefix" in value["extra_specs"] else ""
            suffix = value["extra_specs"]["suffix"] if "suffix" in value["extra_specs"] else ""
        inputs[key] = prefix + uuidgen_deployment + suffix


def process_openstack_ec2credentials(key: str, inputs: dict, stinputs: dict):
    value = stinputs[key]

    if value["type"] == "openstack_ec2credentials" and key.startswith("__"):
        try:
            # remove from inputs array since it is not a real input to pass to the orchestrator
            del inputs[key]
            s3_url = value["url"]

            # Fed-Reg
            if app.settings.fed_reg_url is not None:
                user_groups = fed_reg.get_user_groups(
                    access_token=iam.token["access_token"],
                    with_conn=True,
                    name=session["active_usergroup"],
                    idp_endpoint=session["iss"],
                )
                assert (
                    len(user_groups) < 2
                ), f"Found multiple user groups with name '{session['active_usergroup']}' and issuer '{session['iss']}'"
                assert (
                    len(user_groups) > 0
                ), f"User group with name '{session['active_usergroup']}' and issuer '{session['iss']}' not found"
                user_group = user_groups[0]

                # Find project, provider and region matching service url
                found = False
                for sla in user_group["slas"]:
                    for project in sla["projects"]:
                        _provider = project["provider"]
                        for quota in filter(
                            lambda x: not x["usage"], project["quotas"]
                        ):
                            service = quota["service"]
                            region = service["region"]
                            if (
                                service["type"] == "object-store"
                                and "s3" in service["name"]
                                and service["endpoint"].startswith(s3_url)
                            ):
                                found = True
                                break
                        if found:
                            break
                    if found:
                        break
                if not found:
                    raise Exception("Unable to get EC2 credentials")
                
                # Get target provider details
                provider = fed_reg.get_provider(
                    _provider["uid"],
                    access_token=iam.token["access_token"],
                    with_conn=True,
                )
                assert provider, f"Provider with uid '{provider['uid']}' not found"

                # Retrieve the authentication details matching the current identity provider
                identity_provider = next(
                    filter(
                        lambda x: x["endpoint"] == session["iss"],
                        provider["identity_providers"],
                    )
                )
                auth_method = identity_provider["relationship"]

                # Retrieve the auth_url matching the target region. In older deployments,
                # if not inferred from the provider name, the region is None.
                region = provider["regions"][0]
                identity_service = next(
                    filter(lambda x: x["type"] == "identity", region["services"])
                )

                # Retrieve EC2 access and secret
                access,secret = keystone.get_or_create_ec2_creds(
                    access_token=iam.token["access_token"],
                    project=project["name"],
                    auth_url=identity_service["endpoint"].rstrip("/v3"),
                    identity_provider=auth_method["idp_name"],
                    protocol=auth_method["protocol"],
                )
            # SLAM
            elif app.settings.orchestrator_conf.get("slam_url", None) is not None:
                service = app.cmdb.get_service_by_endpoint(
                    iam.token["access_token"], s3_url
                )
                prj, idp = app.cmdb.get_service_project(
                    iam.token["access_token"],
                    session["iss"],
                    service,
                    session["active_usergroup"],
                )

                if not prj or not idp:
                    raise Exception("Unable to get EC2 credentials")

                if prj and idp:
                    access, secret = keystone.get_or_create_ec2_creds(
                        iam.token["access_token"],
                        prj.get("tenant_name"),
                        service["auth_url"].rstrip("/v3"),
                        idp["name"],
                        idp["protocol"],
                    )

            if access is not None and secret is not None:
                iam_base_url = app.settings.iam_url
                iam_client_id = app.settings.iam_client_id
                iam_client_secret = app.settings.iam_client_secret

                jwt_token = auth.exchange_token_with_audience(
                    iam_base_url,
                    iam_client_id,
                    iam_client_secret,
                    iam.token["access_token"],
                    app.config.get("VAULT_BOUND_AUDIENCE"),
                )

                vaultclient = vaultservice.connect(jwt_token, app.config.get("VAULT_ROLE"))

                secret_path = (
                    session["userid"]
                    + "/services_credential/"
                    + urlparse(s3_url).netloc
                    + "/"
                    + session["active_usergroup"]
                )

                vaultclient.write_secret_dict(
                    None, secret_path, {"aws_access_key": access, "aws_secret_key": secret}
                )

                app.logger.debug(f"EC2 Credentials saved to Vault path {secret_path}")

                test_backet_name = "".join(random.choices(string.ascii_lowercase, k=8))
                s3.create_bucket(
                    s3_url=s3_url, access_key=access, secret_key=secret, bucket=test_backet_name
                )
                s3.delete_bucket(
                    s3_url=s3_url, access_key=access, secret_key=secret, bucket=test_backet_name
                )

                app.logger.debug(
                    f"Bucket creation/deletion test performed with bucket name {test_backet_name}"
                )

        except Forbidden as e:
            app.logger.error("Error while testing S3: {}".format(e))
            flash(
                " Sorry, your request needs a special authorization. \
                        A notification has been sent automatically to the support team. \
                        You will be contacted soon.",
                "danger",
            )
            utils.send_authorization_request_email(
                "Sync&Share aaS for group {}".format(session["active_usergroup"])
            )
            raise


def process_ldap_user(key: str, inputs: dict, stinputs: dict):
    value = stinputs[key]

    if value["type"] == "ldap_user":
        try:
            del inputs[key]

            iam_base_url = app.settings.iam_url
            iam_client_id = app.settings.iam_client_id
            iam_client_secret = app.settings.iam_client_secret

            username = "{}_{}".format(session["userid"], urlparse(iam_base_url).netloc)
            email = session["useremail"]

            jwt_token = auth.exchange_token_with_audience(
                iam_base_url,
                iam_client_id,
                iam_client_secret,
                iam.token["access_token"],
                app.config.get("VAULT_BOUND_AUDIENCE"),
            )

            vaultclient = vaultservice.connect(jwt_token, app.config.get("VAULT_ROLE"))
            luser = LdapUserManager(
                app.config["LDAP_SOCKET"],
                app.config["LDAP_TLS_CACERT_FILE"],
                app.config["LDAP_BASE"],
                app.config["LDAP_BIND_USER"],
                app.config["LDAP_BIND_PASSWORD"],
                vaultclient,
            )

            username, password = luser.create_user(username, email)
            username_input_name = value["inputs"]["username"]
            inputs[username_input_name] = username
            password_input_name = value["inputs"]["password"]
            inputs[password_input_name] = password

        except Exception as e:
            app.logger.error("Error: {}".format(e))
            flash(
                " The deployment submission failed with: {}. \
                        Please try later or contact the admin(s): {}".format(
                    e, app.config.get("SUPPORT_EMAIL")
                ),
                "danger",
            )
            raise InputValidationError(e)


def process_userinfo(key, inputs, stinputs):
    value = stinputs[key]

    if value["type"] == "userinfo":
        if key in inputs and value["attribute"] == "sub":
            inputs[key] = session["userid"]


def process_multiselect(key, inputs, stinputs):
    value = stinputs[key]
    if value["type"] == "multiselect" and key in inputs:
        try:
            lval = request.form.getlist(key)
            if "format" in value and value["format"]["type"] == "string":
                inputs[key] = value["format"]["delimiter"].join(lval)
            else:
                inputs[key] = lval
        except Exception as e:
            app.logger.error("Error processing input {}: {}".format(key, e))
            flash(
                " The deployment submission failed with: {}. \
                        Please try later or contact the admin(s): {}".format(
                    e, app.config.get("SUPPORT_EMAIL")
                ),
                "danger",
            )
            raise InputValidationError(e)


def process_inputs(source_template, inputs, form_data, uuidgen_deployment):
    doprocess = True

    stinputs = copy.deepcopy(source_template["inputs"])

    for k, v in list(stinputs.items()):
        if "group_overrides" in v and session["active_usergroup"] in v["group_overrides"]:
            overrides = v["group_overrides"][session["active_usergroup"]]
            stinputs[k] = {**v, **overrides}
            del stinputs[k]["group_overrides"]

    for key in stinputs.keys():
        try:
            # Manage special type 'dependent_definition' as first
            process_dependent_definition(key, inputs, stinputs)

            # Manage security groups
            process_security_groups(key, inputs, stinputs, form_data)

            # Manage map of string
            process_map(key, inputs, stinputs, form_data)

            # Manage list
            process_list(key, inputs, stinputs, form_data)

            process_ssh_user(key, inputs, stinputs)

            process_random_password(key, inputs, stinputs)

            process_uuidgen(key, inputs, stinputs, uuidgen_deployment)

            process_openstack_ec2credentials(key, inputs, stinputs)

            process_ldap_user(key, inputs, stinputs)

            process_userinfo(key, inputs, stinputs)

            process_multiselect(key, inputs, stinputs)
        except Exception as e:
            msg = f"Error in validating deployment request: {e}"
            flash(msg, "danger")
            app.logger.error(msg)
            doprocess = False

    return doprocess, inputs, stinputs


def create_deployment(
    template,
    inputs,
    stinputs,
    form_data,
    selected_template,
    source_template,
    template_text,
    additionaldescription,
    params,
    storage_encryption,
    vault_secret_uuid,
    vault_secret_key,
):
    access_token = iam.token["access_token"]

    keep_last_attempt = 1 if "extra_opts.keepLastAttempt" in form_data else 0
    feedback_required = 1 if "extra_opts.sendEmailFeedback" in form_data else 0
    provider_timeout_mins = (
        form_data["extra_opts.providerTimeout"]
        if "extra_opts.providerTimeoutSet" in form_data
        else app.config["PROVIDER_TIMEOUT"]
    )

    user_group = (
        session["active_usergroup"]
        if "active_usergroup" in session and session["active_usergroup"] is not None
        else None
    )

    elastic = tosca_helpers.eleasticdeployment(template)
    updatable = source_template["updatable"]

    try:
        rs_json = app.orchestrator.create(
            access_token,
            user_group,
            yaml.dump(template, default_flow_style=False, sort_keys=False),
            inputs,
            keep_last_attempt,
            provider_timeout_mins,
            app.config["OVERALL_TIMEOUT"],
            app.config["CALLBACK_URL"],
        )
    except Exception as e:
        flash(str(e), "danger")
        app.logger.error("Error creating deployment: {}".format(e))
        return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))

    # store data into database
    uuid = rs_json["uuid"]
    deployment = dbhelpers.get_deployment(uuid)
    if deployment is None:
        vphid = rs_json["physicalId"] if "physicalId" in rs_json else ""
        providername = rs_json["cloudProviderName"] if "cloudProviderName" in rs_json else ""

        deployment = Deployment(
            uuid=uuid,
            creation_time=rs_json["creationTime"],
            update_time=rs_json["updateTime"],
            physicalId=vphid,
            description=additionaldescription,
            status=rs_json["status"],
            outputs=json.dumps(rs_json["outputs"]),
            stoutputs=json.dumps(source_template["outputs"]),
            task=rs_json["task"],
            links=json.dumps(rs_json["links"]),
            sub=rs_json["createdBy"]["subject"],
            template=template_text,
            template_metadata=source_template["metadata_file"],
            template_parameters=source_template["parameters_file"],
            selected_template=selected_template,
            inputs=json.dumps(inputs),
            stinputs=json.dumps(stinputs),
            params=json.dumps(params),
            deployment_type=source_template["deployment_type"],
            template_type=source_template["metadata"]["template_type"],
            provider_name=providername,
            user_group=rs_json["userGroup"],
            endpoint="",
            feedback_required=feedback_required,
            keep_last_attempt=keep_last_attempt,
            remote=1,
            issuer=rs_json["createdBy"]["issuer"],
            storage_encryption=storage_encryption,
            vault_secret_uuid=vault_secret_uuid,
            vault_secret_key=vault_secret_key,
            elastic=elastic,
            updatable=updatable,
        )
        dbhelpers.add_object(deployment)

    else:
        flash(
            "Deployment with uuid:{} is already in the database!".format(uuid),
            "warning",
        )


@deployments_bp.route("/submit", methods=["POST"])
@auth.authorized_with_valid_token
def createdep():
    tosca_info, _, _ = tosca.get()
    access_token = iam.token["access_token"]
    # validate input
    request_template = request.args.get("template")
    if request_template not in tosca_info.keys():
        raise ValueError("Template path invalid (not found in current configuration")

    selected_template = request_template
    source_template = tosca_info[selected_template]
    form_data = request.form.to_dict()
    additionaldescription = form_data["additional_description"]

    inputs = extract_inputs(form_data)

    template, template_text = load_template(selected_template)

    if form_data["extra_opts.schedtype"].lower() == "man":
        template = add_sla_to_template(template, form_data["extra_opts.selectedSLA"])
    else:
        remove_sla_from_template(template)
    app.logger.debug(yaml.dump(template, default_flow_style=False))

    uuidgen_deployment = str(uuid_generator.uuid1())

    doprocess, inputs, stinputs = process_inputs(
        source_template, inputs, form_data, uuidgen_deployment
    )

    app.logger.debug(f"Calling orchestrator with inputs: {inputs}")

    if doprocess:
        storage_encryption, vault_secret_uuid, vault_secret_key = add_storage_encryption(
            access_token, inputs
        )
        params = {}  # is it needed??
        create_deployment(
            template,
            inputs,
            stinputs,
            form_data,
            selected_template,
            source_template,
            template_text,
            additionaldescription,
            params,
            storage_encryption,
            vault_secret_uuid,
            vault_secret_key,
        )

    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))


def delete_secret_from_vault(access_token, secret_path):
    vault_bound_audience = app.config.get("VAULT_BOUND_AUDIENCE")
    vault_delete_policy = app.config.get("DELETE_POLICY")
    vault_delete_token_time_duration = app.config.get("DELETE_TOKEN_TIME_DURATION")
    vault_delete_token_renewal_time_duration = app.config.get("DELETE_TOKEN_RENEWAL_TIME_DURATION")
    vault_role = app.config.get("VAULT_ROLE")

    jwt_token = auth.exchange_token_with_audience(
        app.settings.iam_url,
        app.settings.iam_client_id,
        app.settings.iam_client_secret,
        access_token,
        vault_bound_audience,
    )

    vault_client = vaultservice.connect(jwt_token, vault_role)

    delete_token = vault_client.get_token(
        vault_delete_policy,
        vault_delete_token_time_duration,
        vault_delete_token_renewal_time_duration,
    )

    vault_client.delete_secret(delete_token, secret_path)


def add_storage_encryption(access_token, inputs):
    vault_url = app.config.get("VAULT_URL")
    vault_role = app.config.get("VAULT_ROLE")
    vault_bound_audience = app.config.get("VAULT_BOUND_AUDIENCE")
    vault_wrapping_token_time_duration = app.config.get("WRAPPING_TOKEN_TIME_DURATION")
    vault_write_policy = app.config.get("WRITE_POLICY")
    vault_write_token_time_duration = app.config.get("WRITE_TOKEN_TIME_DURATION")
    vault_write_token_renewal_time_duration = app.config.get("WRITE_TOKEN_RENEWAL_TIME_DURATION")

    storage_encryption = 0
    vault_secret_uuid = ""
    vault_secret_key = ""
    if "storage_encryption" in inputs and inputs["storage_encryption"].lower() == "true":
        storage_encryption = 1
        vault_secret_key = "secret"

    if storage_encryption == 1:
        inputs["vault_url"] = vault_url
        vault_secret_uuid = str(uuid_generator.uuid4())
        if "vault_secret_key" in inputs:
            vault_secret_key = inputs["vault_secret_key"]
        app.logger.debug("Storage encryption enabled, appending wrapping token.")

        jwt_token = auth.exchange_token_with_audience(
            app.settings.iam_url,
            app.settings.iam_client_id,
            app.settings.iam_client_secret,
            access_token,
            vault_bound_audience,
        )

        vault_client = vaultservice.connect(jwt_token, vault_role)

        wrapping_token = vault_client.get_wrapping_token(
            vault_wrapping_token_time_duration,
            vault_write_policy,
            vault_write_token_time_duration,
            vault_write_token_renewal_time_duration,
        )

        inputs["vault_wrapping_token"] = wrapping_token
        inputs["vault_secret_path"] = session["userid"] + "/" + vault_secret_uuid

    return storage_encryption, vault_secret_uuid, vault_secret_key


@deployments_bp.route("/sendportsreq", methods=["POST"])
def sendportsrequest():
    form_data = request.form.to_dict()

    try:
        utils.send_ports_request_email(
            form_data["deployment_uuid"],
            email=form_data["email"],
            message=form_data["message"],
        )

        flash(
            "Your request has been sent to the support team. \
                You will receive soon a notification email about your request. Thank you!",
            "success",
        )

    except Exception:
        utils.logexception("sending email:".format())
        flash(
            "Sorry, an error occurred while sending your request. Please retry.",
            "danger",
        )

    return redirect(url_for(SHOW_DEPLOYMENTS_ROUTE))
