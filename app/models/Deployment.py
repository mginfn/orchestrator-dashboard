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

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from app.extensions import db


class Deployment(db.Model):
    __tablename__ = "deployments"
    uuid = db.Column(db.String(36), primary_key=True)
    creation_time = db.Column(db.DateTime, nullable=True)
    update_time = db.Column(db.DateTime, nullable=True)
    physicalId = db.Column(db.String(36), nullable=True)
    description = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(128), nullable=True)
    status_reason = db.Column(db.Text, nullable=True)
    outputs = db.Column(db.Text, nullable=True)
    additional_outputs = db.Column(db.Text, nullable=True)
    stoutputs = db.Column(db.Text, nullable=True)
    task = db.Column(db.String(64), nullable=True)
    links = db.Column(db.Text, nullable=True)
    provider_name = db.Column(db.String(128), nullable=True)
    provider_type = db.Column(db.String(128), nullable=True)
    region_name = db.Column(db.String(128), nullable=True)
    user_group = db.Column(db.String(256), nullable=True)
    endpoint = db.Column(db.String(256), nullable=True)
    selected_template = db.Column(db.Text, nullable=True)
    template = db.Column(db.Text, nullable=True)
    template_parameters = db.Column(db.Text, nullable=True)
    template_metadata = db.Column(db.Text, nullable=True)
    inputs = db.Column(db.Text, nullable=True)
    stinputs = db.Column(db.Text, nullable=True)
    params = db.Column(db.Text, nullable=True)
    deployment_type = db.Column(db.String(16), nullable=True)
    template_type = db.Column(db.String(16), nullable=True)
    locked = db.Column(db.Boolean, nullable=True, default=0)
    feedback_required = db.Column(db.Boolean, nullable=True, default=1)
    keep_last_attempt = db.Column(db.Boolean, nullable=True, default=0)
    remote = db.Column(db.Boolean, nullable=True, default=0)
    issuer = db.Column(db.String(256), nullable=True)
    storage_encryption = db.Column(db.Boolean, nullable=True, default=0)
    vault_secret_uuid = db.Column(db.String(36), nullable=True)
    vault_secret_key = db.Column(db.String(36), nullable=True)
    elastic = db.Column(db.Boolean, nullable=True, default=0)
    updatable = db.Column(db.Boolean, nullable=True, default=0)
    sub = db.Column(db.String(36), ForeignKey("users.sub"))
    user = relationship("User", back_populates="deployments")

    def __repr__(self):
        return "<Deployment {}>".format(self.uuid)
