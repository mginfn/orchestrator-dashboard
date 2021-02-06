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

from app import app
import requests

def url_shorten(url, keyword=None):
    shorturl = None
    api_url = "{}/yourls-api.php".format(app.config.get('YOURLS_SITE'))
    signature = app.config.get('YOURLS_API_SIGNATURE_TOKEN')
    if api_url and signature:
        data = {"signature": signature, "action": "shorturl", "url": url, "format": "json"}
        if keyword is not None:
            data["keyword"] = keyword
        response = requests.post(api_url, data={**data})
        json_resp = response.json()
        if json_resp["status"] == "success" or json_resp["code"] == "error:url":
            shorturl = json_resp["shorturl"]

    return shorturl

