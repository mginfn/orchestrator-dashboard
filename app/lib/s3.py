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

import boto3
import botocore
from werkzeug.exceptions import Forbidden

def create_bucket(access_key, secret_key, s3_url, bucket, **kwargs):

    client = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=s3_url,
        verify=False,
    )

    try:
        response = client.create_bucket(Bucket=bucket)
    except botocore.exceptions.ClientError as error:
        if error.response['ResponseMetadata']['HTTPStatusCode'] == 403:
            raise Forbidden("You don't have the permission for the requested storage resource")
        else:
            raise error

def delete_bucket(access_key, secret_key, s3_url, bucket, **kwargs):

    client = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=s3_url,
        verify=False,
    )
    response = client.delete_bucket(Bucket=bucket)
