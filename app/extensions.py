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
from flask_caching import Cache
from flask_mail import Mail
from flask_migrate import Migrate
from flask_redis import FlaskRedis
from flask_sqlalchemy import SQLAlchemy

from app.lib.tosca_info import ToscaInfo
from app.lib.Vault import Vault

# initialize SQLAlchemy
db: SQLAlchemy = SQLAlchemy()

# initialize Migrate
migrate: Migrate = Migrate()

# initialize Vault
vaultservice: Vault = Vault()

# initialize Redis
redis_client: FlaskRedis = FlaskRedis()

# initialize the cache
cache: Cache = Cache()

mail: Mail = Mail()

tosca: ToscaInfo = ToscaInfo()
