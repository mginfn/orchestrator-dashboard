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

import datetime

from dateutil import parser
from flask import current_app as app
from flask import json

from app.extensions import db
from app.iam import iam
from app.models.Deployment import Deployment
from app.models.Service import Service, UsersGroup
from app.models.User import User


def add_object(object):
    db.session.add(object)
    db.session.commit()


def get_user(subject):
    return User.query.get(subject)


def get_users():
    users = User.query.order_by(User.family_name.desc(), User.given_name.desc()).all()
    return users


def update_user(subject, data):
    User.query.filter_by(sub=subject).update(data)
    db.session.commit()


def get_admins_email():
    admins = User.query.filter_by(role="admin").all()
    return [user.email for user in admins]


def get_ssh_pub_key(subject):
    user = User.query.get(subject)
    return user.sshkey


def delete_ssh_key(subject):
    User.query.get(subject).sshkey = None
    db.session.commit()


def update_deployment(depuuid, data):
    Deployment.query.filter_by(uuid=depuuid).update(data)
    db.session.commit()


def get_user_deployments(user_sub):
    return Deployment.query.filter_by(sub=user_sub).all()


def get_deployment(uuid):
    return Deployment.query.get(uuid)


def getdeploymenttype(dep):
    deptype = ""
    if "cloudProviderEndpoint" in dep:
        endpoint = dep["cloudProviderEndpoint"]
        if "deploymentType" in endpoint:
            etype = endpoint["deploymentType"]
            if (
                etype == "OPENSTACK"
                or etype == "OPENNEBULA"
                or etype == "AWS"
                or etype == "OTC"
                or etype == "AZURE"
            ):
                deptype = "CLOUD"
            else:
                deptype = etype

    return deptype


def updatedeploymentsstatus(deployments, userid):
    result = {}
    deps = []
    iids = []

    # update deployments status in database
    for dep_json in deployments:
        uuid = dep_json["uuid"]
        iids.append(uuid)

        # sanitize date
        dt = parser.parse(dep_json["creationTime"])
        dep_json["creationTime"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        dt = parser.parse(dep_json["updateTime"])
        dep_json["updateTime"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        update_time = datetime.datetime.strptime(dep_json["updateTime"], "%Y-%m-%d %H:%M:%S")
        creation_time = datetime.datetime.strptime(dep_json["creationTime"], "%Y-%m-%d %H:%M:%S")

        providername = dep_json["cloudProviderName"] if "cloudProviderName" in dep_json else ""
        max_length = 65535
        status_reason = dep_json.get("statusReason", "")[:max_length]

        vphid = dep_json["physicalId"] if "physicalId" in dep_json else ""

        dep = get_deployment(uuid)

        if dep is not None:
            if (
                dep.status != dep_json["status"]
                or dep.provider_name != providername
                or str(dep.status_reason or "") != status_reason
            ):
                dep.update_time = update_time
                dep.physicalId = vphid
                dep.status = dep_json["status"]
                dep.outputs = json.dumps(dep_json["outputs"])
                dep.task = dep_json["task"]
                dep.links = json.dumps(dep_json["links"])
                dep.remote = 1
                dep.provider_name = providername
                dep.status_reason = status_reason

                db.session.add(dep)
                db.session.commit()

            deps.append(dep)
        else:
            app.logger.info("Deployment with uuid:{} not found!".format(uuid))

            # retrieve template
            access_token = iam.token["access_token"]

            try:
                template = app.orchestrator.get_template(access_token, uuid)
            except Exception:
                template = ""

            # insert missing deployment in database
            endpoint = dep_json["outputs"]["endpoint"] if "endpoint" in dep_json["outputs"] else ""

            deployment = Deployment(
                uuid=uuid,
                creation_time=creation_time,
                update_time=update_time,
                physicalId=vphid,
                description="",
                status=dep_json["status"],
                outputs=json.dumps(dep_json["outputs"]),
                stoutputs="",
                task=dep_json["task"],
                links=json.dumps(dep_json["links"]),
                sub=userid,
                template=template,
                template_parameters="",
                template_metadata="",
                selected_template="",
                inputs="",
                stinputs="",
                params="",
                deployment_type=getdeploymenttype(dep_json),
                provider_name=providername,
                user_group=dep_json.get("userGroup"),
                endpoint=endpoint,
                remote=1,
                locked=0,
                feedback_required=0,
                keep_last_attempt=0,
                issuer=dep_json["createdBy"]["issuer"],
                storage_encryption=0,
                vault_secret_uuid="",
                vault_secret_key="",
                elastic=0,
                updatable=0,
            )

            db.session.add(deployment)
            db.session.commit()

            deps.append(deployment)

    # check delete in progress or missing
    dd = Deployment.query.filter(
        Deployment.sub == userid, Deployment.status == "DELETE_IN_PROGRESS"
    ).all()

    for d in dd:
        uuid = d.uuid
        if uuid not in iids:
            time_string = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            d.status = "DELETE_COMPLETE"
            d.update_time = time_string
            db.session.add(d)
            db.session.commit()

    result["deployments"] = deps
    result["iids"] = iids
    return result


def cvdeployments(deps):
    deployments = []
    for d in deps:
        deployments.append(cvdeployment(d))
    return deployments


def cvdeployment(d):
    deployment = Deployment(
        uuid=d.uuid,
        creation_time=d.creation_time,
        update_time=d.update_time,
        physicalId="" if d.physicalId is None else d.physicalId,
        description=d.description,
        status=d.status,
        status_reason=d.status_reason,
        outputs=json.loads(d.outputs.replace("\n", "\\n"))
        if (d.outputs is not None and d.outputs != "")
        else "",
        stoutputs=json.loads(d.stoutputs.replace("\n", "\\n"))
        if (d.stoutputs is not None and d.stoutputs != "")
        else "",
        task=d.task,
        links=json.loads(d.links.replace("\n", "\\n"))
        if (d.links is not None and d.links != "")
        else "",
        sub=d.sub,
        template=d.template,
        template_parameters=d.template_parameters if d.template_parameters is not None else "",
        template_metadata=d.template_metadata if d.template_metadata is not None else "",
        selected_template=d.selected_template,
        inputs=json.loads(d.inputs.replace("\n", "\\n"))
        if (d.inputs is not None and d.inputs != "")
        else "",
        stinputs=json.loads(d.stinputs.replace("\n", "\\n"))
        if (d.stinputs is not None and d.stinputs != "")
        else "",
        params=d.params,
        deployment_type=d.deployment_type,
        provider_name="" if d.provider_name is None else d.provider_name,
        user_group="" if d.user_group is None else d.user_group,
        endpoint=d.endpoint,
        remote=d.remote,
        locked=d.locked,
        issuer=d.issuer,
        feedback_required=d.feedback_required,
        keep_last_attempt=d.keep_last_attempt,
        storage_encryption=d.storage_encryption,
        vault_secret_uuid="" if d.vault_secret_uuid is None else d.vault_secret_uuid,
        vault_secret_key="" if d.vault_secret_key is None else d.vault_secret_key,
        elastic=d.elastic,
        updatable=d.updatable,
    )
    return deployment


def update_deployments(subject):
    issuer = app.settings.iam_url
    if not issuer.endswith("/"):
        issuer += "/"

    # retrieve deployments from orchestrator
    access_token = iam.token["access_token"]
    deployments_from_orchestrator = []

    deployments_from_orchestrator = app.orchestrator.get_deployments(
        access_token, created_by="{}@{}".format(subject, issuer)
    )

    update_deployments_status(deployments_from_orchestrator, subject)


def update_deployments_status(deployments_from_orchestrator, subject):
    if not deployments_from_orchestrator:
        return

    iids = updatedeploymentsstatus(deployments_from_orchestrator, subject)["iids"]

    # retrieve deployments from DB
    deployments = cvdeployments(get_user_deployments(subject))
    for dep in deployments:
        newremote = dep.remote
        if dep.uuid not in iids:
            if dep.remote == 1:
                newremote = 0
        else:
            if dep.remote == 0:
                newremote = 1
        if dep.remote != newremote:
            update_deployment(dep.uuid, dict(remote=newremote))


def get_services(visibility, groups=[]):
    services = []
    if visibility == "public":
        services = Service.query.filter_by(visibility="public").all()
    if visibility == "private":
        services = []
        ss = Service.query.all()
        for s in ss:
            s_groups = [g.name for g in s.groups]
            if not set(s_groups).isdisjoint(groups):
                services.append(s)
    if visibility == "all":
        services = Service.query.all()

    return services


def get_service(id):
    return Service.query.get(id)


def __update_service(s, data):
    s.name = data.get("name")
    s.description = data.get("description")
    s.url = data.get("url")
    if data.get("icon"):
        s.icon = data.get("icon")
    s.visibility = data.get("visibility")
    s.groups = []

    if s.visibility == "private":
        for g in data.get("groups"):
            group = UsersGroup.query.filter_by(name=g).first()
            if not group:
                group = UsersGroup()
                group.name = g
            s.groups.append(group)


def update_service(id, data):
    s = Service.query.filter_by(id=id).first()
    __update_service(s, data)
    db.session.add(s)
    db.session.commit()


def delete_service(id):
    service = Service.query.filter_by(id=id).first()
    db.session.delete(service)
    db.session.commit()


def add_service(data):
    s = Service()
    __update_service(s, data)
    db.session.add(s)
    db.session.commit()
