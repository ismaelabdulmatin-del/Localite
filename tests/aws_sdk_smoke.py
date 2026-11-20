#!/usr/bin/env python3
import os
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


ENDPOINT = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:4566")
SESSION = boto3.session.Session(
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
)
S3 = SESSION.client(
    "s3",
    config=Config(s3={"addressing_style": "path"}),
)
SQS = SESSION.client("sqs")
DDB = SESSION.client("dynamodb")
IAM = SESSION.client("iam")
STS = SESSION.client("sts")
SUFFIX = uuid.uuid4().hex[:12]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run():
    check(STS.get_caller_identity()["Account"] == "123456789012", "STS identity")
    print("ok STS GetCallerIdentity")

    bucket = f"localite-sdk-{SUFFIX}"
    key = "nested/example.txt"
    S3.create_bucket(Bucket=bucket)
    try:
        S3.put_object(Bucket=bucket, Key=key, Body=b"Localite SDK smoke test")
        check(S3.get_object(Bucket=bucket, Key=key)["Body"].read() == b"Localite SDK smoke test", "S3 GetObject")
        check(S3.list_objects_v2(Bucket=bucket)["KeyCount"] == 1, "S3 ListObjectsV2")
    finally:
        try:
            S3.delete_object(Bucket=bucket, Key=key)
            S3.delete_bucket(Bucket=bucket)
        except ClientError:
            pass
    print("ok S3 create/put/get/list/delete")

    queue_name = f"localite-sdk-{SUFFIX}"
    queue_url = SQS.create_queue(QueueName=queue_name)["QueueUrl"]
    try:
        SQS.send_message(QueueUrl=queue_url, MessageBody="Localite SDK smoke test")
        messages = SQS.receive_message(QueueUrl=queue_url, WaitTimeSeconds=0)["Messages"]
        check(messages and messages[0]["Body"] == "Localite SDK smoke test", "SQS ReceiveMessage")
        SQS.delete_message(QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"])
    finally:
        try:
            SQS.delete_queue(QueueUrl=queue_url)
        except ClientError:
            pass
    print("ok SQS create/send/receive/delete")

    table_name = f"LocaliteSdk{SUFFIX}"
    DDB.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    DDB.get_waiter("table_exists").wait(
        TableName=table_name,
        WaiterConfig={"Delay": 1, "MaxAttempts": 10},
    )
    try:
        DDB.put_item(TableName=table_name, Item={"id": {"S": "one"}, "value": {"S": "initial"}})
        DDB.update_item(
            TableName=table_name,
            Key={"id": {"S": "one"}},
            UpdateExpression="SET #value = :value",
            ExpressionAttributeNames={"#value": "value"},
            ExpressionAttributeValues={":value": {"S": "updated"}},
        )
        item = DDB.get_item(TableName=table_name, Key={"id": {"S": "one"}})["Item"]
        check(item["value"]["S"] == "updated", "DynamoDB UpdateItem/GetItem")
        queried = DDB.query(
            TableName=table_name,
            KeyConditionExpression="#id = :id",
            ExpressionAttributeNames={"#id": "id"},
            ExpressionAttributeValues={":id": {"S": "one"}},
        )["Items"]
        check(len(queried) == 1, "DynamoDB Query")
        check(len(DDB.scan(TableName=table_name)["Items"]) == 1, "DynamoDB Scan")
        DDB.delete_item(TableName=table_name, Key={"id": {"S": "one"}})
    finally:
        try:
            DDB.delete_table(TableName=table_name)
        except ClientError:
            pass
    print("ok DynamoDB create/put/get/update/query/scan/delete")

    user_name = f"localite-sdk-{SUFFIX}"
    try:
        IAM.create_user(UserName=user_name)
        check(IAM.get_user(UserName=user_name)["User"]["UserName"] == user_name, "IAM GetUser")
    finally:
        try:
            IAM.delete_user(UserName=user_name)
        except ClientError:
            pass
    check(
        all(user["UserName"] != user_name for user in IAM.list_users()["Users"]),
        "IAM ListUsers cleanup",
    )
    print("ok IAM create/get/list/delete")


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        print(f"FAILED against {ENDPOINT}: {error}")
        raise
