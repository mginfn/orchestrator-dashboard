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

from flask import render_template, request, Blueprint
from app import app

errors_bp = Blueprint('errors', __name__,
                           template_folder='templates',
                           static_folder='static'
                           )


@errors_bp.app_errorhandler(403)
def forbidden(error):
    return render_template('403.html', message=error.description)


@errors_bp.app_errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', request.path)
    return render_template('404.html'), 404


@errors_bp.app_errorhandler(500)
def internal_server_error(error):
    app.logger.error('Server Error: %s', error)
    return render_template('500.html', support_email=app.config.get('SUPPORT_EMAIL')), 500
