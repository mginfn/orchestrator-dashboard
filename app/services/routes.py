# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2022
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

from app import app
from app.lib import utils
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask import send_from_directory
from app.lib import auth, settings, dbhelpers
from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
#UPLOAD_FOLDER = "/tmp/uploads/"
app.config['MAX_CONTENT_LENGTH'] = 1024 * 100

services_bp = Blueprint('services_bp', __name__,
                           template_folder='templates',
                           static_folder='static')

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

app.jinja_env.filters['enum2str'] = utils.enum_to_string

@services_bp.route('/list')
@services_bp.route('/list/<visibility>')
@auth.authorized_with_valid_token
def list(visibility='public'):
    groups = session['usergroups'] if visibility == 'private' else []
    services = dbhelpers.get_services(visibility, groups)
    return render_template("services.html", services=services)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file(file):
    filename = None
    if file and allowed_file(file.filename):
        upload_folder = app.config['UPLOAD_FOLDER']
        filename = secure_filename(file.filename)
        fullfilename = os.path.join(upload_folder, filename)
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        file.save(fullfilename)
    return filename


@services_bp.route('/admin/list')
@auth.authorized_with_valid_token
@auth.only_for_admin
def list_as_admin():
    services = dbhelpers.get_services(visibility='all')
    return render_template("services.html", services=services)

@services_bp.route('/admin/add', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def add():
    if request.method == 'POST':
        service = request.form.to_dict()
        file = request.files["icon"]
        filename = upload_file(file)
        service["icon"] = filename if filename else ""
        service["groups"] = request.form.getlist('groups')
        if 'is_public' in request.form:
            service["visibility"] = 'public'
            del service['is_public']
        else:
            service["visibility"] = 'private'
        try:
            dbhelpers.add_service(service)
            flash('You have successfully added the service.', 'success')
        except Exception as e:
            flash('Something went wrong: {}'.format(e), 'danger')
        return redirect(url_for('services_bp.list_as_admin'))

    service = {}
    return render_template("editservice.html", service=service, groups=session['supported_usergroups'])


@services_bp.route('/admin/delete/<int:id>', methods=['POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def delete(id):
    service = dbhelpers.get_service(id)
    if service.icon != '':
        fullfilename = os.path.join(app.config.get("UPLOAD_FOLDER"), service.icon)
        if os.path.exists(fullfilename):
            os.remove(fullfilename)
    dbhelpers.delete_service(id)
    flash('You have successfully deleted the service.', 'success')
    return redirect(url_for('services_bp.list_as_admin'))


@services_bp.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def edit(id=None):

    if request.method == 'POST':
        service = request.form.to_dict()
        file = request.files["icon"]
        filename = upload_file(file)
        groups = request.form.getlist('groups')
        service['groups'] = groups

        if filename:
            service["icon"] = filename

        if 'is_public' in request.form:
            service["visibility"] = 'public'
            service['groups'] = ""
            del service['is_public']
        else:
            service["visibility"] = 'private'

        dbhelpers.update_service(id, service)
        flash('You have successfully updated the service.', 'success')
        return redirect(url_for('services_bp.list_as_admin'))

    service = dbhelpers.get_service(id)
    # update groups select
    groups = [s for s in session['supported_usergroups'] if s not in service.groups]

    servicedict = service.__dict__
    servicedict['groups'] = [g.name for g in service.groups]

    return render_template("editservice.html", service=servicedict, groups=groups)


@services_bp.route('/showimg')
def showimg():
    filename = request.args['filename']
    if filename and filename != "":
        return send_from_directory(app.config.get('UPLOAD_FOLDER'), filename)