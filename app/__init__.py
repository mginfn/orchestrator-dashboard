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
import os
from logging.config import dictConfig

from flask import Flask
from flask_migrate import upgrade
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from app.deployments.routes import deployments_bp
from app.errors.routes import errors_bp
from app.extensions import cache, db, mail, migrate, redis_client, tosca, vaultservice
from app.home.routes import home_bp
from app.iam import make_iam_blueprint
from app.lib import utils
from app.lib.cmdb import Cmdb
from app.lib.orchestrator import Orchestrator
from app.lib.settings import Settings
from app.providers.routes import providers_bp
from app.services.routes import services_bp
from app.swift.routes import swift_bp
from app.users.routes import users_bp
from app.vault.routes import vault_bp


def create_app():
    """
    Create and configure the Flask application.

    This function initializes a Flask application, configures it, registers blueprints,
    and sets up various extensions such as the database connection, authentication,
    and error handling.

    Returns:
        Flask: The configured Flask application instance.

    Example:
        app = create_app()
        app.run()
    """
    app = Flask(__name__, instance_relative_config=True)
    app.wsgi_app = ProxyFix(app.wsgi_app)

    app.config.from_object("config.default")
    app.config.from_file("../config/schemas/metadata_schema.json", json.load)

    if os.environ.get("TESTING", "").lower() == "true":
        app.config.from_file("../tests/resources/config.json", json.load)
    else:
        app.config.from_file("config.json", json.load)

    app.secret_key = app.config["SECRET_KEY"]
    CSRFProtect(app)

    settings = Settings(app)
    app.settings = settings  # attach the Settings object to the app

    orchestrator = Orchestrator(settings.orchestrator_url)
    app.orchestrator = orchestrator

    cmdb = Cmdb(app.settings.orchestrator_conf["cmdb_url"])
    app.cmdb = cmdb

    app.config["MAX_CONTENT_LENGTH"] = 1024 * 100  # put in the config.py

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        app.config.from_file("vault-config.json", json.load)

    if app.config.get("FEATURE_S3CREDS_MENU") == "yes":
        app.config.from_file("s3-config.json", json.load)

    profile = app.config.get("CONFIGURATION_PROFILE")
    if profile is not None and profile != "default":
        app.config.from_object("config." + profile)

    db.init_app(app)
    migrate.init_app(app, db, compare_server_default=True, compare_type=True)

    with app.app_context():
        upgrade(directory="migrations", revision="head")

    app.config["CACHE_TYPE"] = "RedisCache"
    app.config["CACHE_REDIS_URL"] = app.config.get("REDIS_URL")

    redis_kwargs = {
        "socket_timeout": app.config["REDIS_SOCKET_TIMEOUT"],
    }
    redis_client.init_app(app, **redis_kwargs)
    redis_client.ping()

    cache.init_app(app)

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        vaultservice.init_app(app)

    mail.init_app(app)

    # initialize ToscaInfo
    tosca.init_app(app, redis_client)

    # initialize iam blueprint
    app.iam_blueprint = make_iam_blueprint(
        client_id=app.config["IAM_CLIENT_ID"],
        client_secret=app.config["IAM_CLIENT_SECRET"],
        base_url=app.config["IAM_BASE_URL"],
        redirect_to="home_bp.home",
    )

    app.jinja_env.filters["tojson_pretty"] = utils.to_pretty_json
    app.jinja_env.filters["extract_netinterface_ips"] = utils.extract_netinterface_ips
    app.jinja_env.filters["intersect"] = utils.intersect
    app.jinja_env.filters["python_eval"] = utils.python_eval
    app.jinja_env.filters["enum2str"] = utils.enum_to_string
    app.jinja_env.filters["str2bool"] = utils.str2bool
    app.jinja_env.filters["contains_sensitive_keyword"] = utils.contains_sensitive_keyword

    register_blueprints(app)

    # Configure logging using dictConfig
    configure_logging(app)

    return app


def register_blueprints(app):
    """
    Register Flask blueprints for different application modules.

    Parameters:
    - app (Flask): The Flask application to which the blueprints will be registered.

    Blueprints:
    - `errors_bp`: Handles error pages and error-related routes.
    - `app.iam_blueprint`: Handles IAM routes under "/login".
    - `home_bp`: Handles routes related to the home page ("/").
    - `users_bp`: Handles routes related to user management ("/users").
    - `deployments_bp`: Handles routes related to deployments ("/deployments").
    - `providers_bp`: Handles routes related to providers ("/providers").
    - `swift_bp`: Handles routes related to Swift integration ("/swift").
    - `services_bp`: Handles routes related to services ("/services").

    Conditional Blueprints:
    - If the Flask app has the "FEATURE_VAULT_INTEGRATION" set to "yes":
        - `vault_bp`: Handles routes related to Vault integration ("/vault").
    """
    app.register_blueprint(errors_bp)

    app.register_blueprint(app.iam_blueprint, url_prefix="/login")

    app.register_blueprint(home_bp, url_prefix="/")

    app.register_blueprint(users_bp, url_prefix="/users")

    app.register_blueprint(deployments_bp, url_prefix="/deployments")

    app.register_blueprint(providers_bp, url_prefix="/providers")

    app.register_blueprint(swift_bp, url_prefix="/swift")

    app.register_blueprint(services_bp, url_prefix="/services")

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        app.register_blueprint(vault_bp, url_prefix="/vault")


def validate_log_level(log_level):
    """
    Validates that the provided log level is a valid choice.

    Parameters:
    - log_level (str): The log level to validate.

    Raises:
    - ValueError: If the log level is not one of ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'].
    """
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if log_level not in valid_log_levels:
        raise ValueError(f"Invalid log level: {log_level}. Valid log levels are {valid_log_levels}")


def configure_logging(app):
    """
    Configures logging for a Flask application based on the provided app configuration.

    This function sets up a logging configuration using the provided log level from the app's configuration.
    It configures a stream handler with a custom formatter for the 'app' logger and the root logger.

    Parameters:
    - app (Flask): The Flask application instance.
    """
    level = app.config.get("LOG_LEVEL")
    validate_log_level(level)

    if level == "DEBUG":
        msg_format = (
            "%(asctime)s - %(levelname)s - %(message)s [%(funcName)s() in %(pathname)s:%(lineno)s]"
        )
    else:
        msg_format = "%(asctime)s - %(levelname)s - %(message)s"

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "handlers": {
            "stream_handler": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "custom_formatter",
            },
        },
        "formatters": {
            "custom_formatter": {
                "format": msg_format,
            },
        },
        "loggers": {
            "app": {
                "handlers": ["stream_handler"],
                "level": level,
                "propagate": False,  # Do not propagate messages to the root logger
            },
            "root": {
                "handlers": [],
                "level": level,
            },
        },
        "root": {
            "handlers": ["stream_handler"],
            "level": level,
        },
    }
    dictConfig(logging_config)


#### TODO
# add route /info
# from app import info
