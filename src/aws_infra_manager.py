import boto3
from botocore.exceptions import ClientError
import json


class AWSInfraManager:

    # =============================
    # INIT
    # =============================
    def __init__(self, region="us-east-1"):
        self.region = region
        self.s3 = boto3.client("s3", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.sts = boto3.client("sts", region_name=region)
        self.account_id = self.sts.get_caller_identity()["Account"]


    # =============================
    # TEAM → S3 BUCKET FORMATTER
    # =============================
    @staticmethod
    def format_team_to_bucket(team_name: str) -> str:
        """
        DE_27_Team4 → de-27-team4
        """
        return team_name.lower().replace("_", "-")


    # =============================
    # S3 BUCKET (IDEMPOTENT)
    # =============================
    def create_team_bucket(self, team_name: str):
        """
        Creates a team S3 bucket in us-east-1.
        Safe to re-run.
        """

        bucket_name = self.format_team_to_bucket(team_name)

        try:
            self.s3.create_bucket(Bucket=bucket_name)
            print(f"✅ Bucket created successfully: {bucket_name}")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code in ["BucketAlreadyOwnedByYou", "BucketAlreadyExists"]:
                print(f"⚠ Bucket already exists: {bucket_name}")
            else:
                raise

        return bucket_name


    # =============================
    # GLUE EXECUTION ROLE
    # =============================
    def create_glue_role(self, team_name, managed_policy_arns=None):
        """
        Creates:
            <team>-glue-role
        With Glue trust policy.
        """

        team = team_name.lower().replace("_", "-")
        role_name = f"{team}-glue-role"

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "glue.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        try:
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Glue execution role for {team_name}",
                Tags=[{"Key": "Team", "Value": team_name}]
            )
            print(f"✅ Glue role created: {role_name}")

        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                print(f"⚠ Glue role already exists: {role_name}")
            else:
                raise

        # Attach managed policies if provided
        if managed_policy_arns:
            for policy_arn in managed_policy_arns:
                self.attach_policy_if_missing(role_name, policy_arn)

        return role_name


    # =============================
    # EC2 INSTANCE ROLE
    # =============================
    def create_ec2_role(self, team_name, managed_policy_arns=None):
        """
        Creates:
            <team>-ec2-role
        With EC2 trust policy.
        """

        team = team_name.lower().replace("_", "-")
        role_name = f"{team}-ec2-role"

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        try:
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"EC2 role for {team_name}",
                Tags=[{"Key": "Team", "Value": team_name}]
            )
            print(f"✅ EC2 role created: {role_name}")

        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                print(f"⚠ EC2 role already exists: {role_name}")
            else:
                raise

        # Attach managed policies if provided
        if managed_policy_arns:
            for policy_arn in managed_policy_arns:
                self.attach_policy_if_missing(role_name, policy_arn)

        return role_name


    # =============================
    # ATTACH POLICY SAFELY
    # =============================
    def attach_policy_if_missing(self, role_name, policy_arn):
        attached = self.iam.list_attached_role_policies(
            RoleName=role_name
        )["AttachedPolicies"]

        already_attached = any(
            p["PolicyArn"] == policy_arn for p in attached
        )

        if already_attached:
            print(f"✔ Policy already attached: {policy_arn}")
        else:
            self.iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            print(f"🔗 Attached policy → {role_name}")

    # =============================
    # MWAA (AIRFLOW) S3 BUCKETS
    # =============================
    def create_mwaa_bucket(self, team_name):
        """
        Creates ONE MWAA bucket using ONLY team name:
            <team>

        And creates folders:
            dags/
            plugins/
            requirements/
        """

        team = self.format_team_to_bucket(team_name)
        bucket_name = team   # ✅ NO MWAA PREFIX

        try:
            self.s3.create_bucket(Bucket=bucket_name)
            print(f"✅ Created MWAA bucket: {bucket_name}")

        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ["BucketAlreadyOwnedByYou", "BucketAlreadyExists"]:
                print(f"⚠ MWAA bucket exists: {bucket_name}")
            else:
                raise

        # Create folder placeholders
        folders = ["dags/", "plugins/", "requirements/"]

        for folder in folders:
            self.s3.put_object(
                Bucket=bucket_name,
                Key=folder
            )
            print(f"📁 Created folder: s3://{bucket_name}/{folder}")

        return {
            "bucket": bucket_name,
            "dags": f"{bucket_name}/dags/",
            "plugins": f"{bucket_name}/plugins/",
            "requirements": f"{bucket_name}/requirements/"
        }



    # =============================
    # MWAA EXECUTION ROLE
    # =============================
    def create_mwaa_execution_role(self, team_name):
        team = self.format_team_to_bucket(team_name)
        role_name = f"{team}-mwaa-exec-role"  

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "airflow-env.amazonaws.com",
                        "airflow.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }]
        }

        try:
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"MWAA execution role for {team_name}",
                Tags=[{"Key": "Team", "Value": team_name}]
            )
            print(f"✅ Created MWAA role: {role_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                raise

        # ✅ COMPLETE MWAA EXECUTION POLICY (NETWORK + CELERY + SQS + LOGS + S3)
        exec_policy = {
            "Version": "2012-10-17",
            "Statement": [

                # ✅ SQS for Celery
                {
                    "Effect": "Allow",
                    "Action": [
                        "sqs:SendMessage",
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                        "sqs:GetQueueUrl"
                    ],
                    "Resource": "*"
                },

                # ✅ Required ENI + VPC networking
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateNetworkInterface",
                        "ec2:AttachNetworkInterface",
                        "ec2:DetachNetworkInterface",
                        "ec2:DeleteNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeVpcs"
                    ],
                    "Resource": "*"
                },

                # ✅ Required VPC Endpoints
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateVpcEndpoint",
                        "ec2:DescribeVpcEndpoints",
                        "ec2:ModifyVpcEndpoint"
                    ],
                    "Resource": "*"
                },

                # ✅ S3 DAG access
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": f"*"
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": f"*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetBucketLocation",
                        "s3:GetBucketPublicAccessBlock",
                        "s3:GetAccountPublicAccessBlock"
                    ],
                    "Resource": "*"
                },

                # ✅ CloudWatch Logs
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:GetLogEvents"
                    ],
                    "Resource": "*"
                },

                # ✅ Glue Jobs from DAGs
                {
                    "Effect": "Allow",
                    "Action": [
                        "glue:StartJobRun",
                        "glue:GetJobRun",
                        "glue:GetJobRuns",
                        "glue:BatchStopJobRun"
                    ],
                    "Resource": "*"
                },

                # ✅ Pass roles to Glue / MWAA workers
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{self.account_id}:role/*"
                }
            ]
        }

        self.iam.put_role_policy(
            RoleName=role_name,
            PolicyName="MWAAExecutionPolicy",
            PolicyDocument=json.dumps(exec_policy)
        )

        print("✅ MWAA execution policy attached")

        return role_name

    
    def attach_secrets_manager_access(self, role_name, team_name):
        """
        Grants READ access to AWS Secrets Manager for team-prefixed secrets only.
        Safe for MWAA / Glue / EC2 execution roles.
        """

        team = self.format_team_to_bucket(team_name)

        secrets_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SecretsManagerTeamRead",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:DescribeSecret"
                    ],
                    "Resource": [
                        f"arn:aws:secretsmanager:{self.region}:{self.account_id}:secret:{team}*"
                    ]
                }
            ]
        }

        self.iam.put_role_policy(
            RoleName=role_name,
            PolicyName="TeamSecretsManagerReadAccess",
            PolicyDocument=json.dumps(secrets_policy)
        )

        print(f"✅ Secrets Manager access attached to role: {role_name}")

    def update_mwaa_trust_policy(self, role_name):
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "airflow-env.amazonaws.com",
                        "airflow.amazonaws.com",
                        "sagemaker.amazonaws.com",
                        "glue.amazonaws.com",
                        "lakeformation.amazonaws.com",
                        "bedrock.amazonaws.com",
                        "scheduler.amazonaws.com",
                        "athena.amazonaws.com",
                        "redshift.amazonaws.com",
                        "emr-serverless.amazonaws.com",
                        "datazone.amazonaws.com"
                    ]
                },
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "sts:SetContext",
                    "sts:SetSourceIdentity"
                ],
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": self.account_id
                    }
                }
            }]
        }

        self.iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )

        print(f"✅ MWAA trust policy fixed for {role_name}")







