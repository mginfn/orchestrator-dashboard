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
import logging
import json
import sys
import socket

from flask import Flask
from flask_alembic import Alembic
from sqlalchemy import Table, Column, String, MetaData
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_migrate import upgrade

from app.extensions import db, vaultservice, mail, migrate, redis_client, cache, tosca
from app.iam import make_iam_blueprint
from app.lib import utils
from app.lib.orchestrator import Orchestrator
from app.lib.settings import Settings

from app.home.routes import home_bp
from app.errors.routes import errors_bp
from app.users.routes import users_bp
from app.deployments.routes import deployments_bp
from app.providers.routes import providers_bp
from app.swift.routes import swift_bp
from app.services.routes import services_bp
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
    app.secret_key = "30bb7cf2-1fef-4d26-83f0-8096b6dcc7a3"
    app.config.from_object('config.default')
    app.config.from_file('config.json', json.load)
    app.config.from_file('../config/schemas/metadata_schema.json', json.load)

    settings = Settings(app)
    app.settings = settings # attach the Settings object to the app

    orchestrator = Orchestrator(settings.orchestrator_url)
    app.orchestrator = orchestrator

    app.config['MAX_CONTENT_LENGTH'] = 1024 * 100 # put in the config.py

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        app.config.from_file('vault-config.json', json.load)

    if app.config.get("FEATURE_S3CREDS_MENU") == "yes":
        app.config.from_file('s3-config.json', json.load)

    profile = app.config.get('CONFIGURATION_PROFILE')
    if profile is not None and profile != 'default':
        app.config.from_object('config.' + profile)

    db.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        db.create_all()
        upgrade(directory='migrations', revision='head')

    app.config['CACHE_TYPE'] = 'RedisCache'
    app.config['CACHE_REDIS_URL'] = app.config.get('REDIS_URL')
    redis_client.init_app(app)
    cache.init_app(app)

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        vaultservice.init_app(app)

    mail.init_app(app)

    # initialize ToscaInfo
    tosca.init_app(app, redis_client)

    app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json
    app.jinja_env.filters['extract_netinterface_ips'] = utils.extract_netinterface_ips
    app.jinja_env.filters['intersect'] = utils.intersect
    app.jinja_env.filters['python_eval'] = utils.python_eval
    app.jinja_env.filters['enum2str'] = utils.enum_to_string
    app.jinja_env.filters['str2bool'] = utils.str2bool


    app.register_blueprint(errors_bp)

    iam_base_url = app.config['IAM_BASE_URL']

    iam_blueprint = make_iam_blueprint(
        client_id=app.config['IAM_CLIENT_ID'],
        client_secret=app.config['IAM_CLIENT_SECRET'],
        base_url=iam_base_url,
        redirect_to='home_bp.home'
    )
    app.register_blueprint(iam_blueprint, url_prefix="/login")

    app.register_blueprint(home_bp, url_prefix="/")

    app.register_blueprint(users_bp, url_prefix="/users")

    app.register_blueprint(deployments_bp, url_prefix="/deployments")

    app.register_blueprint(providers_bp, url_prefix="/providers")

    app.register_blueprint(swift_bp, url_prefix="/swift")

    app.register_blueprint(services_bp, url_prefix="/services")

    if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
        app.register_blueprint(vault_bp, url_prefix="/vault")

    # logging
    loglevel = app.config.get("LOG_LEVEL") if app.config.get("LOG_LEVEL") else "INFO"
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % loglevel)

    logging.basicConfig(level=numeric_level)

    return app


#### TODO
# add route /info
#from app import info

