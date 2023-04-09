import argparse

import boto3
from os import getenv
from dotenv import load_dotenv
import logging
from botocore.exceptions import ClientError

load_dotenv()

def init_client():
    try:
        client = boto3.client("s3",
                              aws_access_key_id = getenv("aws_access_key_id"),
                              aws_secret_access_key = getenv("aws_secret_access_key"),
                              aws_session_token = getenv("aws_session_token"),
                              region_name = getenv("aws_region_name"))
        client.list_buckets()
        return client
    except ClientError as e:
        logging.error(e)
    except:
        logging.error(("Unexpected error"))

def list_buckets(aws_s3_client):
    try:
        return aws_s3_client.list_buckets()
    except ClientError as e:
        logging.error(e)
        return False

def create_bucket(aws_s3_client, bucket_name, region="us-west-2"):
    try:
        location = {'LocationConstraint': region}
        aws_s3_client.create_bucket(
            Bucket = bucket_name,
            CreateBucketConfiguration = location
        )
    except ClientError as e:
        logging.error(e)
        return False
    return True

def delete_bucket(aws_s3_client, bucket_name):
    try:
        aws_s3_client.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True


def bucket_exists(aws_s3_client, bucket_name):
    try:
        response = aws_s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.error(e)
        return False

    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def download_file_and_upload(aws_s3_client, bucket_name, url, file_name, keep_local=False):
    from urllib.request import urlopen
    import io
    allowed_extensions = [".bmp", ".jpg", ".jpeg", ".png", ".webp", ".mp4"]
    for ext in allowed_extensions:
        allowed = url.endswith(ext)
        if allowed:
            with urlopen(url) as response:
                content = response.read()
                try:
                    aws_s3_client.upload_fileobj(Fileobj=io.BytesIO(content), Bucket=bucket_name, Key=file_name+ext)

                except Exception as e:
                    logging.error(e)

            if keep_local:
                with open(file_name,mode='wb') as jpg_file:
                    jpg_file.write(content)

            return f"https://s3-us-east-1.amazonaws.com/{bucket_name}/{file_name}"
        else:
            continue


def set_object_access_policy(aws_s3_client, bucket_name, file_name):
    try:
        response = aws_s3_client.put_object_acl(
            ACL="public-read",
            Bucket=bucket_name,
            Key=file_name
        )
    except ClientError as e:
        logging.error(e)
        return False
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def generate_public_read_policy(bucket_name):
    import json
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }

    return json.dumps(policy)


def create_bucket_policy(aws_s3_client, bucket_name):
    aws_s3_client.put_bucket_policy(
        Bucket=bucket_name, Policy=generate_public_read_policy(bucket_name)
    )
    print("Bucket policy created successfully")


def read_bucket_policy(aws_s3_client, bucket_name):
    try:
        policy = aws_s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = policy["Policy"]
        print(policy_str)
    except ClientError as e:
        logging.error(e)
        return False


parser = argparse.ArgumentParser()
parser.add_argument("bucket")
parser.add_argument("operation")
args = parser.parse_args()

bucket_name = args.bucket
operation = args.operation

s3_client = init_client()

if s3_client:
    if operation == "list_bucket":
        buckets = list_buckets(s3_client)
        if buckets:
            for bucket in buckets['Buckets']:
                print(f"    {bucket['Name']}")

    elif operation == "create_bucket":
        new_bucket = create_bucket(s3_client, bucket_name)

        buckets = list_buckets(s3_client)
        if buckets:
            for bucket in buckets['Buckets']:
                print(f"    {bucket['Name']}")

    elif operation == "delete_bucket":
        delete_bucket(s3_client, bucket_name)
        buckets = list_buckets(s3_client)
        if buckets:
            for bucket in buckets['Buckets']:
                print(f"    {bucket['Name']}")

    elif operation == "exist_bucket":
        bucket_exists(s3_client, bucket_name)
        buckets = list_buckets(s3_client)
        if buckets:
            for bucket in buckets['Buckets']:
                print(f"    {bucket['Name']}")

    elif operation == "upload_file":
        file_cont = input("enter file url.. allowed extensions: .bmp, .jpg, .jpeg, .png, .webp, .mp4")
        file_name = input("enter file name")
        file = download_file_and_upload(s3_client, bucket_name, file_cont, file_name,)
        buckets = list_buckets(s3_client)
        if buckets:
            for bucket in buckets['Buckets']:
                print(f"    {bucket['Name']}")

    elif operation == "set_object_access_policy":
        file_name = input("enter file name")
        file = set_object_access_policy(s3_client, bucket_name, file_name)

    elif operation == "create_bucket_policy":
        file = create_bucket_policy(s3_client, bucket_name)

    elif operation == "read_bucket_policy":
            file_name = input("enter file name")
            file = read_bucket_policy(s3_client, bucket_name)

    else:
        print("Unknown operation")

else:
    print("Please, upload aws credentials")
