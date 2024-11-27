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

import requests
from flask import current_app as app, Blueprint, render_template, flash, request
from app.providers import sla
from app.iam import iam
from app.lib import auth, fed_reg


providers_bp = Blueprint(
    "providers_bp", __name__, template_folder="templates", static_folder="static"
)


@providers_bp.route("/slas")
@auth.authorized_with_valid_token
def getslas():
    slas = []
    access_token = iam.token["access_token"]

    # Fed-Reg
    app.logger.debug("FED_REG_URL: {}".format(app.settings.fed_reg_url))
    if app.settings.fed_reg_url is not None:
        slas = fed_reg.retrieve_slas_from_specific_user_group(access_token=access_token)

    # SLAM
    elif app.settings.orchestrator_conf.get("slam_url", None) is not None:
        try:
            app.logger.debug(
                "SLAM_URL: {}".format(app.settings.orchestrator_conf["slam_url"])
            )
            slas = sla.get_slas(
                access_token,
                app.settings.orchestrator_conf["slam_url"],
                app.settings.orchestrator_conf["cmdb_url"],
            )
            app.logger.debug("SLAs: {}".format(slas))

        except Exception as e:
            flash("Error retrieving SLAs list: \n" + str(e), "warning")

    return render_template("sla.html", slas=slas)


@providers_bp.route("/get_monitoring_info")
@auth.authorized_with_valid_token
def get_monitoring_info():
    provider = request.args.get("provider", None)
    serviceid = request.args.get("service_id", None)
    # servicetype = request.args.get('service_type',None)

    access_token = iam.token["access_token"]

    headers = {"Authorization": "bearer %s" % access_token}
    url = (
        app.settings.orchestrator_conf["monitoring_url"]
        + "/monitoring/adapters/zabbix/zones/indigo/types/infrastructure/groups/"
        + provider
        + "/hosts/"
        + serviceid
    )
    response = requests.get(url, headers=headers)

    monitoring_data = {}

    if response.ok:
        try:
            monitoring_data = response.json()["result"]["groups"][0]["paasMachines"][0][
                "services"
            ][0]["paasMetrics"]
        except Exception:
            app.logger.debug("Error getting monitoring data")

    return render_template("monitoring_metrics.html", monitoring_data=monitoring_data)
