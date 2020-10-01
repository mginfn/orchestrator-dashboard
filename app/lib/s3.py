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
        if error.response['Error']['Code'] == 'SignatureDoesNotMatch':
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
