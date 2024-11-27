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


class Settings:
    """
    A class to manage application settings and configuration values.

    This class is responsible for encapsulating various configuration settings used
    throughout the application. It provides a convenient way to access these settings
    and maintain a clear separation between configuration values and application logic.

    Args:
        app (Flask): The Flask application instance to retrieve configuration values.

    Attributes:
        settings_dir (str): The directory path for application settings.
        tosca_dir (str): The directory path for TOSCA templates.
        tosca_params_dir (str): The directory path for TOSCA parameters.
        tosca_metadata_dir (str): The directory path for TOSCA metadata.
        iam_url (str): The IAM base URL.
        iam_client_id (str): The IAM client ID.
        iam_client_secret (str): The IAM client secret.
        iam_groups (list): List of IAM group memberships.
        orchestrator_url (str): The orchestrator's base URL.
        orchestrator_conf (dict): Configuration parameters for the orchestrator, including
            CMDB URL, SLAM URL, IM URL, monitoring URL, and Vault URL.
    """

    def __init__(self, app):
        self.settings_dir = app.config["SETTINGS_DIR"] + "/"
        self.tosca_dir = app.config["TOSCA_TEMPLATES_DIR"] + "/"
        self.tosca_params_dir = app.config.get("SETTINGS_DIR") + "/tosca-parameters"
        self.tosca_metadata_dir = app.config.get("SETTINGS_DIR") + "/tosca-metadata"

        self.iam_url = app.config["IAM_BASE_URL"]
        self.iam_client_id = app.config.get("IAM_CLIENT_ID")
        self.iam_client_secret = app.config.get("IAM_CLIENT_SECRET")
        self.iam_groups = app.config.get("IAM_GROUP_MEMBERSHIP")

        temp_slam_url = app.config.get("SLAM_URL")

        self.fed_reg_url = app.config.get("FED_REG_URL", None)
        
        self.orchestrator_url = app.config["ORCHESTRATOR_URL"]
        self.orchestrator_conf = {
            "cmdb_url": app.config.get("CMDB_URL"),
            "slam_url": None if temp_slam_url is None else temp_slam_url + "/rest/slam",
            "im_url": app.config.get("IM_URL"),
            "monitoring_url": app.config.get("MONITORING_URL", ""),
            "vault_url": app.config.get("VAULT_URL"),
            "fed_reg_url": self.fed_reg_url,
        }
