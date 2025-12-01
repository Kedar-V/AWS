import boto3
import json
import botocore


class AWSPolicyManager:

    # =============================
    # INIT
    # =============================
    def __init__(self, region="us-east-1"):
        self.region = region
        self.iam = boto3.client("iam", region_name=region)
        self.sts = boto3.client("sts", region_name=region)
        self.account_id = self.sts.get_caller_identity()["Account"]
        self.SERVICE_BUILDERS = {
            "EC2":           self.policy_ec2,
            "S3":            self.policy_s3,
            "Lambda":        self.policy_lambda,
            "EventBridge":   self.policy_eventbridge,
            "ECR":           self.policy_ecr,
            "ECS":           self.policy_ecs,
            "CloudWatch":    self.policy_cloudwatch,
            "SageMaker":     self.policy_sagemaker,
            "SageMakerAI":   self.policy_sagemaker_ai,
            "RDS":           self.policy_rds,
            "Glue":          self.policy_glue,
            "ServiceCatalog": self.policy_servicecatalog,
            "DynamoDB": self.policy_dynamodb,
            "Bedrock": self.policy_bedrock,
            "Airflow": self.policy_mwaa,
            "Policy": self.policy_network,
            "CloudShell": self.policy_cloudshell
        }



    # =========================================================
    # DOMAIN POLICY BUILDER
    # =========================================================
    def build_domain_policy(self, team, services):
        """
        Merge statements from multiple service policies into
        a single domain policy document.
        """
        statements = []

        for svc in services:
            builder = self.SERVICE_BUILDERS[svc]

            doc = builder(team)
            svc_statements = doc.get("Statement", [])

            if isinstance(svc_statements, dict):
                svc_statements = [svc_statements]

            statements.extend(svc_statements)

        return {
            "Version": "2012-10-17",
            "Statement": statements
        }

    # =========================================================
    # CREATE + ATTACH DOMAIN POLICIES
    # =========================================================
    def create_team_domain_policies(self, team_name, DOMAIN_GROUPS, enabled_domains=None):
        """
        Creates merged domain policies and attaches them
        to the main team IAM group.
        """

        group_name = team_name

        if enabled_domains is None:
            enabled_domains = list(DOMAIN_GROUPS.keys())

        for domain in enabled_domains:

            services = DOMAIN_GROUPS[domain]

            pol_doc  = self.build_domain_policy(team_name, services)
            pol_name = f"{team_name}-{domain}Access"
            pol_desc = f"{domain} domain access for team {team_name}"

            arn = self.create_or_update_policy(
                pol_name,
                pol_doc,
                pol_desc
            )

            self.attach_policy_to_group(
                policy_arn=arn,
                group_name=group_name
            )

            print(f"📌 Attached {pol_name} → {group_name}")



    # =============================
    # GENERIC POLICY WRAPPER
    # =============================
    def create_or_update_policy(self, policy_name, policy_document, description=""):
        """
        Idempotent IAM managed policy creator/updater.
        - Rotates versions
        - Deletes oldest non-default when >=5
        """
        try:
            response = self.iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
                Description=description
            )
            print(f"✅ Created policy: {policy_name}")
            return response["Policy"]["Arn"]

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "EntityAlreadyExists":
                raise

            print(f"⚠ Policy {policy_name} exists → updating")

            policy_arn = f"arn:aws:iam::{self.account_id}:policy/{policy_name}"

            versions = self.iam.list_policy_versions(
                PolicyArn=policy_arn
            )["Versions"]

            non_default = sorted(
                [v for v in versions if not v["IsDefaultVersion"]],
                key=lambda x: x["CreateDate"]
            )

            if len(non_default) >= 4:
                oldest = non_default[0]["VersionId"]
                print(f"🧹 Deleting old version: {oldest}")
                self.iam.delete_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=oldest
                )

            self.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(policy_document),
                SetAsDefault=True
            )

            print(f"🔄 Updated policy: {policy_name}")
            return policy_arn


    # =========================================================
    # SERVICE POLICIES
    # =========================================================

    def policy_ec2(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*",
                        "ec2:GetSecurityGroupsForVpc",
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeLaunchTemplateVersions",
                        "ec2-instance-connect:SendSSHPublicKey"
                    ],
                    "Resource": "*"
                },
                {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Action": ["ec2:CreateTags", "ec2:DeleteTags"],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:StartInstances",
                        "ec2:StopInstances",
                        "ec2:RebootInstances",
                        "ec2:TerminateInstances"
                    ],
                    "Resource": f"arn:aws:ec2:*:{self.account_id}:instance/*"
                }
            ]
        }


    def policy_s3(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:CreateBucket",
                        "s3:List*",
                        "s3:Get*",
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject"
                    ],
                    "Resource": ["*"]
                },
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketVersioning", "s3:PutBucketVersioning"], "Resource": "*"}
            ]
        }


    def policy_lambda(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": [
                    "lambda:ListFunctions",
                    "lambda:GetFunction",
                    "lambda:ListVersionsByFunction",
                    "lambda:ListEventSourceMappings",
                    "lambda:GetAccountSettings"
                ], "Resource": "*"},
                {"Effect": "Allow", "Action": [
                    "lambda:CreateFunction",
                    "lambda:UpdateFunctionCode",
                    "lambda:UpdateFunctionConfiguration",
                    "lambda:DeleteFunction",
                    "lambda:PublishVersion",
                    "lambda:CreateAlias",
                    "lambda:UpdateAlias",
                    "lambda:DeleteAlias"
                ], "Resource": f"arn:aws:lambda:*:{self.account_id}:function:{team}-*"},
                {"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
                 "Resource": f"arn:aws:lambda:*:{self.account_id}:function:{team}-*"}
            ]
        }


    def policy_eventbridge(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "EventBridgeReadOnly", "Effect": "Allow",
                 "Action": ["events:List*", "events:Describe*", "pipes:List*", "pipes:Describe*", "scheduler:List*", "scheduler:Describe*"],
                 "Resource": "*"},
                {"Sid": "EventBridgeTeamWrite", "Effect": "Allow",
                 "Action": ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets", "events:TagResource", "events:UntagResource"],
                 "Resource": [f"arn:aws:events:*:{self.account_id}:rule/{team}-*"]},
                {"Sid": "PipesTeamWrite", "Effect": "Allow",
                 "Action": ["pipes:CreatePipe", "pipes:UpdatePipe", "pipes:DeletePipe", "pipes:StartPipe", "pipes:StopPipe", "pipes:TagResource", "pipes:UntagResource"],
                 "Resource": [f"arn:aws:pipes:*:{self.account_id}:pipe/{team}-*"]}
            ]
        }


    def policy_ecr(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "ECRReadOnly", "Effect": "Allow",
                 "Action": ["ecr:DescribeRepositories", "ecr:ListImages", "ecr:GetAuthorizationToken"],
                 "Resource": "*"},
                {"Sid": "ECRCreateTeamRepo", "Effect": "Allow",
                 "Action": ["ecr:CreateRepository"], "Resource": "*",
                 "Condition": {"StringLike": {"ecr:RepositoryName": f"{team}*"}}},
                {"Sid": "ECRTeamRepoAccess", "Effect": "Allow",
                 "Action": [
                     "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                     "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
                     "ecr:CompleteLayerUpload", "ecr:PutImage"
                 ],
                 "Resource": f"arn:aws:ecr:*:{self.account_id}:repository/{team}*"}
            ]
        }


    def policy_ecs(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "ECSListDescribe", "Effect": "Allow",
                 "Action": ["ecs:List*", "ecs:Describe*"], "Resource": "*"},
                {"Sid": "ServiceDiscoveryReadOnly", "Effect": "Allow",
                 "Action": ["servicediscovery:List*", "servicediscovery:Get*"], "Resource": "*"},
                {"Sid": "ECSCreateTeamCluster", "Effect": "Allow",
                 "Action": ["ecs:CreateCluster", "ecs:DeleteCluster"], "Resource": "*",
                 "Condition": {"StringLike": {"ecs:ClusterName": f"{team}*"}}}
            ]
        }


    def policy_cloudwatch(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "CloudWatchRO", "Effect": "Allow",
                 "Action": ["cloudwatch:List*", "cloudwatch:Describe*", "logs:Describe*", "events:List*"],
                 "Resource": "*"},
                {"Sid": "TeamLogsWrite", "Effect": "Allow",
                 "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": f"arn:aws:logs:*:{self.account_id}:log-group:/aws/{team}/*"}
            ]
        }


    def policy_rds(self, team):
        team_prefix = team.lower().replace("_", "-")

        return {
            "Version": "2012-10-17",
            "Statement": [

                # ======================================================
                # 1. RDS READ / DISCOVERY (Console Required)
                # ======================================================
                {
                    "Sid": "RDSReadOnlyAll",
                    "Effect": "Allow",
                    "Action": [
                        "rds:List*",
                        "rds:Describe*"
                    ],
                    "Resource": "*"
                },

                # ======================================================
                # 2. CREATE TEAM DBs ONLY (Name + Tag Enforced)
                # ======================================================
                {
                    "Sid": "RDSCreateTeamDB",
                    "Effect": "Allow",
                    "Action": [
                        "rds:CreateDBInstance",
                        "rds:CreateDBCluster"
                    ],
                    "Resource": "*"
                    # "Condition": {
                    #     "StringLike": {
                    #         "rds:db-instance-identifier": f"{team}*",
                    #         "rds:db-cluster-identifier": f"{team}*"
                    #     },
                    #     "StringEquals": {
                    #         "aws:RequestTag/Team": team
                    #     }
                    # }
                },

                # ======================================================
                # 3. MODIFY / DELETE ONLY TEAM DBS
                # ======================================================
                {
                    "Sid": "RDSModifyDeleteTeamDB",
                    "Effect": "Allow",
                    "Action": [
                        "rds:ModifyDBInstance",
                        "rds:DeleteDBInstance",
                        "rds:StartDBInstance",
                        "rds:StopDBInstance"
                    ],
                    "Resource": [
                        f"arn:aws:rds:*:{self.account_id}:db:{team}*",
                        f"arn:aws:rds:*:{self.account_id}:cluster:{team}*"
                    ]
                },

                # ======================================================
                # 4. ✅ SECRETS MANAGER (RDS CREDENTIALS)
                # ======================================================
                {
                    "Sid": "RDSSecretsManagerTeamAccess",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:CreateSecret",
                        "secretsmanager:GetSecretValue",
                        "secretsmanager:PutSecretValue",
                        "secretsmanager:UpdateSecret",
                        "secretsmanager:DeleteSecret",
                        "secretsmanager:TagResource",
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:ListSecrets"
                    ],
                    "Resource": [
                        f"arn:aws:secretsmanager:{self.region}:{self.account_id}:secret:{team_prefix}*"
                    ]
                },

                {
                    "Sid": "RDSSecretsManager",
                    "Effect": "Allow",
                    "Action": [
                        "secretsmanager:CreateSecret",                        
                        "secretsmanager:DescribeSecret",
                        "secretsmanager:ListSecrets"
                    ],
                    "Resource": [
                        "*"
                    ]
                },

                # ======================================================
                # 5. ✅ KMS FOR ENCRYPTED RDS SECRETS
                # ======================================================
                {
                    "Sid": "KMSForRDSSecrets",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*"
                },

                # ======================================================
                # 6. ✅ RDS ↔ SECRETS MANAGER INTEGRATION
                # ======================================================
                {
                    "Sid": "RDSSecretsIntegration",
                    "Effect": "Allow",
                    "Action": [
                        "rds:AddRoleToDBInstance",
                        "rds:RemoveRoleFromDBInstance",
                        "rds:DescribeDBInstances"
                    ],
                    "Resource": [
                        f"arn:aws:rds:*:{self.account_id}:db:{team}*"
                    ]
                }
            ]
        }



    def policy_glue(self, team):
        # team = team.lower().replace("_", "-")
        return {
            "Version": "2012-10-17",
            "Statement": [
                    {
                "Sid": "GlueListDescribe",
                "Effect": "Allow",
                "Action": [
                    "glue:List*",
                    "glue:Get*",
                    "glue:Describe*"
                ],
                "Resource": "*"
            },
            {
                "Sid": "GlueCreateTeamResources",
                "Effect": "Allow",
                "Action": [
                    "glue:CreateDatabase",
                    "glue:CreateTable",
                    "glue:SearchTables",
                    "glue:CreateCrawler",
                    "glue:CreateJob",
                    "glue:CreateTrigger",
                    "glue:CreateWorkflow",
                    "glue:CreatePartition",
                    "glue:UpdateJob"
                ],
                "Resource": "*"
            },
            {
                "Sid": "GlueInteractiveSessionAccess",
                "Effect": "Allow",
                "Action": [
                    "glue:CreateSession",
                    "glue:GetSession",
                    "glue:ListSessions",
                    "glue:StopSession",
                    "glue:CreateConnection",
                    "glue:GetConnection",
                    "glue:UpdateConnection",
                    "glue:DeleteConnection",
                    "glue:GetDevEndpoint",
                    "glue:ListDevEndpoints",
                    "glue:GetJob",
                    "glue:ListJobs",
                    "glue:BatchGetJobs",
                    "glue:CreateScript",
                    "glue:RunDataPreviewStatement",
                    "glue:Run*",
                ],
                "Resource": [
                    "*"
                ]
            },
            {
                "Sid": "GlueTagStudioSessions",
                "Effect": "Allow",
                "Action": [
                    "glue:TagResource",
                    "glue:UntagResource"
                ],
                "Resource": [
                    f"arn:aws:glue:*:{self.account_id}:session/*",
                    f"arn:aws:glue:*:{self.account_id}:session/glue-studio-datapreview-*"
                ]
            },
            {
                "Sid": "GlueModifyDeleteTeam",
                "Effect": "Allow",
                "Action": [
                    "glue:DeleteDatabase",
                    "glue:DeleteTable",
                    "glue:DeleteCrawler",
                    "glue:DeleteJob",
                    "glue:DeleteTrigger",
                    "glue:DeleteWorkflow",
                    "glue:DeletePartition",
                    "glue:UpdateDatabase",
                    "glue:UpdateTable",
                    "glue:UpdateCrawler",
                    "glue:UpdateJob",
                    "glue:UpdateTrigger",
                    "glue:UpdateWorkflow",
                    "glue:CreateCrawler",
                    "glue:StartCrawler",
                    "glue:StopCrawler",
                    "glue:GetCrawler",
                    "glue:GetCrawlers",
                    "glue:GetCrawlerMetrics",
                    "glue:BatchGetCrawlers"
                ],
                "Resource": [
                    f"arn:aws:glue:*:{self.account_id}:database/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:table/DE_27_Team7*/*",
                    f"arn:aws:glue:*:{self.account_id}:crawler/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:job/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:trigger/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:workflow/DE_27_Team7*"
                ]
            },
            {
                "Sid": "GlueRunTeamOnly",
                "Effect": "Allow",
                "Action": [
                    "glue:StartCrawler",
                    "glue:StartJobRun",
                    "glue:StartTrigger",
                    "glue:StopCrawler",
                    "glue:StopTrigger",
                    "glue:BatchStopJobRun"
                ],
                "Resource": [
                    f"arn:aws:glue:*:{self.account_id}:crawler/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:job/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:trigger/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:workflow/DE_27_Team7*"
                ]
            },
            {
                "Sid": "GlueTagTeamResources",
                "Effect": "Allow",
                "Action": [
                    "glue:TagResource",
                    "glue:UntagResource"
                ],
                "Resource": [
                    f"arn:aws:glue:*:{self.account_id}:database/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:table/DE_27_Team7*/*",
                    f"arn:aws:glue:*:{self.account_id}:crawler/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:job/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:trigger/DE_27_Team7*",
                    f"arn:aws:glue:*:{self.account_id}:workflow/DE_27_Team7*"
                ]
            },
            {
                "Sid": "AllowPassTeamGlueRole",
                "Effect": "Allow",
                "Action": [
                    "iam:PassRole"
                ],
                "Resource": f"arn:aws:iam::{self.account_id}:role/de-27-team7-glue-role"
            },
            {
                "Sid": "AllowAttachInlinePolicyToTeamGlueRole",
                "Effect": "Allow",
                "Action": [
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:AttachRolePolicy",
    				"iam:DetachRolePolicy"
                ],
                "Resource": f"arn:aws:iam::{self.account_id}:role/de-27-team7-glue-role"
            },
            {
                "Sid": "IAMConsoleSupport",
                "Effect": "Allow",
                "Action": [
                    "iam:ListRoles",
                    "iam:GetRole"
                ],
                "Resource": "*"
            }
            ]
        }


    def policy_dynamodb(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["dynamodb:List*", "dynamodb:Describe*", "dynamodb:Query", "dynamodb:Scan"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["dynamodb:CreateTable", "dynamodb:ImportTable"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem"],
                 "Resource": f"arn:aws:dynamodb:*:{self.account_id}:table/{team}*"}
            ]
        }


    def policy_bedrock(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["bedrock:List*", "bedrock:Get*", "bedrock:BatchGet*"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                 "Resource": f"arn:aws:bedrock:{self.region}::foundation-model/*"}
            ]
        }


    def policy_mwaa(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["airflow:ListEnvironments", "airflow:GetEnvironment", "airflow:TagResource", "airflow:CreateEnvironment", "airflow:UpdateEnvironment"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["airflow:CreateCliToken", "airflow:CreateWebLoginToken"],
                 "Resource": "*"}
            ]
        }


    def policy_network(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["ec2:Describe*"], "Resource": "*"},
                {"Effect": "Deny", "Action": ["ec2:CreateVpc", "ec2:DeleteVpc", "ec2:CreateSubnet"], "Resource": "*"}
            ]
        }


    def policy_cloudshell(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "CloudShellMinimalAccess", "Effect": "Allow",
                 "Action": [
                     "cloudshell:CreateSession",
                     "cloudshell:GetFileDownloadUrl",
                     "cloudshell:GetFileUploadUrl",
                     "cloudshell:PutCredentials",
                     "cloudshell:CreateEnvironment"
                 ],
                 "Resource": "*"}
            ]
        }
    
    def policy_sagemaker(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "sagemaker:CreateNotebookInstance",
                        "sagemaker:StartNotebookInstance",
                        "sagemaker:StopNotebookInstance",
                        "sagemaker:CreateTrainingJob",
                        "sagemaker:Describe*"
                    ],
                    "Resource": "*"
                }
            ]
        }

    def policy_sagemaker_ai(self, team):
        return {
        "Version": "2012-10-17",
        "Statement": [

            # /////////////////////////////////////////
            # // SAGEMAKER NOTEBOOKS
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "sagemaker:CreateNotebookInstance",
                    "sagemaker:StartNotebookInstance",
                    "sagemaker:StopNotebookInstance",
                    "sagemaker:DeleteNotebookInstance",
                    "sagemaker:DescribeNotebookInstance",
                    "sagemaker:ListNotebookInstances",
                    "sagemaker:CreatePresignedNotebookInstanceUrl"
                ],
                "Resource": "*"
            },

            # /////////////////////////////////////////
            # // TRAINING / PROCESSING / TRANSFORM JOBS
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "sagemaker:CreateTrainingJob",
                    "sagemaker:DescribeTrainingJob",
                    "sagemaker:StopTrainingJob",

                    "sagemaker:CreateProcessingJob",
                    "sagemaker:DescribeProcessingJob",
                    "sagemaker:StopProcessingJob",

                    "sagemaker:CreateTransformJob",
                    "sagemaker:DescribeTransformJob",
                    "sagemaker:StopTransformJob"
                ],
                "Resource": "*"
            },

            # /////////////////////////////////////////
            # // MODELS + ENDPOINTS
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "sagemaker:CreateModel",
                    "sagemaker:DescribeModel",
                    "sagemaker:DeleteModel",

                    "sagemaker:CreateEndpoint",
                    "sagemaker:CreateEndpointConfig",
                    "sagemaker:DeleteEndpoint",
                    "sagemaker:DeleteEndpointConfig",
                    "sagemaker:DescribeEndpoint",
                    "sagemaker:DescribeEndpointConfig"
                ],
                "Resource": "*"
            },

            # /////////////////////////////////////////
            # // FEATURE STORE + PIPELINES
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "sagemaker:CreateFeatureGroup",
                    "sagemaker:DescribeFeatureGroup",
                    "sagemaker:PutRecord",

                    "sagemaker:CreateExperiment",
                    "sagemaker:DescribeExperiment",

                    "sagemaker:CreateTrial",
                    "sagemaker:CreateTrialComponent",

                    "sagemaker:CreatePipeline",
                    "sagemaker:StartPipelineExecution",
                    "sagemaker:DescribePipeline",
                    "sagemaker:DescribePipelineExecution"
                ],
                "Resource": "*"
            },

            # /////////////////////////////////////////
            # // REQUIRED READ-ONLY ACCESS FOR SAGEMAKER STUDIO
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "sagemaker:List*",
                    "sagemaker:Describe*"
                ],
                "Resource": "*"
            },

            # /////////////////////////////////////////
            # // S3 ACCESS (TEAM-SCOPED)
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{team}",
                    f"arn:aws:s3:::{team}/*"
                ]
            },

            # /////////////////////////////////////////
            # // ECR (TEAM-SCOPED)
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:PutImage"
                ],
                "Resource": f"arn:aws:ecr:*:{self.account_id}:repository/{team}*"
            },

            # /////////////////////////////////////////
            # // CLOUDWATCH LOGS (TEAM-SCOPED)
            # /////////////////////////////////////////
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": f"arn:aws:logs:*:{self.account_id}:log-group:/aws/sagemaker/{team}/*"
            }
        ]
    }

    def policy_servicecatalog(self, team):
        return {
            "Version": "2012-10-17",
            "Statement": [

                # ----------------------------------------------------------
                # Allow console discovery (cannot be scoped by team)
                # ----------------------------------------------------------
                {
                    "Sid": "ServiceCatalogReadOnly",
                    "Effect": "Allow",
                    "Action": [
                        "servicecatalog:List*",
                        "servicecatalog:Describe*",
                        "servicecatalog:Get*",
                        "servicecatalog:ScanProvisionedProducts"
                    ],
                    "Resource": "*"
                },

                # ----------------------------------------------------------
                # Explicit deny provisioning so they cannot launch products
                # ----------------------------------------------------------
                {
                    "Sid": "ServiceCatalogDenyProvisioning",
                    "Effect": "Deny",
                    "Action": [
                        "servicecatalog:ProvisionProduct",
                        "servicecatalog:TerminateProvisionedProduct",
                        "servicecatalog:UpdateProvisionedProduct"
                    ],
                    "Resource": "*"
                }
            ]
        }
    
    def policy_network(self, team):
        """
        Read-only network discovery so teams can:
        • see the shared VPC
        • select shared subnets
        • select shared security groups
        • pick subnet groups when creating RDS
        • pick AZs and VPC for ECS/Lambda/RDS/EKS/Glue

        Zero write privileges.
        """

        return {
            "Version": "2012-10-17",
            "Statement": [

                # ======================================================
                # 1. VPC READ-ONLY ACCESS (required for all consoles)
                # ======================================================
                {
                    "Sid": "VPCReadOnly",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeDhcpOptions",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeNetworkAcls",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeSecurityGroupRules"
                    ],
                    "Resource": "*"
                },

                # ======================================================
                # 2. RDS Subnet Groups READ-ONLY
                # ======================================================
                {
                    "Sid": "DescribeDBSubnetGroups",
                    "Effect": "Allow",
                    "Action": [
                        "rds:DescribeDBSubnetGroups",
                        "rds:ListTagsForResource"
                    ],
                    "Resource": "*"
                },

                # ======================================================
                # 3. Shared VPC Tag visibility (console needs this)
                # ======================================================
                {
                    "Sid": "ReadVpcTags",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeTags"
                    ],
                    "Resource": "*"
                },

                # ======================================================
                # 4. Prevent any network modification
                # ======================================================
                {
                    "Sid": "DenyNetworkWrite",
                    "Effect": "Deny",
                    "Action": [
                        "ec2:CreateVpc",
                        "ec2:DeleteVpc",
                        "ec2:CreateSubnet",
                        "ec2:DeleteSubnet",
                        "ec2:CreateRouteTable",
                        "ec2:DeleteRouteTable",
                        "ec2:CreateInternetGateway",
                        "ec2:DeleteInternetGateway",
                        "ec2:AttachInternetGateway",
                        "ec2:DetachInternetGateway",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:AuthorizeSecurityGroupEgress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupEgress",
                        "ec2:DeleteSecurityGroup",
                        "ec2:GetSecurityGroupsForVpc",
                    ],
                    "Resource": "*"
                }
            ]
        }

    def policy_mwaa_group_prereqs(self):

        return {
            "Version": "2012-10-17",
            "Statement": [

                # ---------------- DataZone ----------------
                {
                    "Sid": "AllowDataZoneRead",
                    "Effect": "Allow",
                    "Action": [
                        "datazone:ListDomains",
                        "datazone:GetDomain",
                        "datazone:CreateDomain",
                        "datazone:DeleteDomain",
                        "datazone:ListProjects"
                    ],
                    "Resource": "*"
                },

                # ---------------- SageMaker Studio ----------------
                {
                    "Sid": "SageMakerStudioConsole",
                    "Effect": "Allow",
                    "Action": [
                        "sagemaker:ListDomains",
                        "sagemaker:DescribeDomain",
                        "sagemaker:ListUserProfiles",
                        "sagemaker:DescribeUserProfile",
                        "sagemaker:ListApps",
                        "sagemaker:DescribeApp"
                    ],
                    "Resource": "*"
                },

                # ---------------- KMS ----------------
                {
                    "Sid": "KMSConsoleRead",
                    "Effect": "Allow",
                    "Action": [
                        "kms:ListAliases",
                        "kms:DescribeKey"
                    ],
                    "Resource": "*"
                },

                # ---------------- DocumentDB Elastic ----------------
                {
                    "Sid": "DocumentDBElasticConsoleRead",
                    "Effect": "Allow",
                    "Action": [
                        "docdb-elastic:ListClusters",
                        "docdb-elastic:GetCluster"
                    ],
                    "Resource": "*"
                },

                # ---------------- Redshift Serverless ----------------
                {
                    "Sid": "RedshiftServerlessConsoleRead",
                    "Effect": "Allow",
                    "Action": [
                        "redshift-serverless:ListWorkgroups",
                        "redshift-serverless:GetWorkgroup",
                        "redshift-serverless:ListNamespaces",
                        "redshift-serverless:GetNamespace"
                    ],
                    "Resource": "*"
                },

                # ---------------- Redshift Provisioned ----------------
                {
                    "Sid": "RedshiftProvisionedConsoleRead",
                    "Effect": "Allow",
                    "Action": [
                        "redshift:DescribeClusters",
                        "redshift:ViewQueriesInConsole"
                    ],
                    "Resource": "*"
                },

                # ---------------- ✅ MWAA NETWORK INTERFACES FIX ----------------
                {
                    "Sid": "AllowMWAANetworkInterfaces",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateNetworkInterface",
                        "ec2:DeleteNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:AttachNetworkInterface",
                        "ec2:DetachNetworkInterface",
                        "ec2:ModifyNetworkInterfaceAttribute",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeVpcs"
                    ],
                    "Resource": "*"
                },

                # ---------------- PassRole ----------------
                {
                    "Sid": "AllowPassRoleForMWAAAndStudio",
                    "Effect": "Allow",
                    "Action": [
                        "iam:PassRole",
                        "iam:ListRoles",
                        "iam:GetRole",
                        "iam:ListAttachedRolePolicies",
                        "iam:ListRolePolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": [
                        "*"
                    ]
                },

                {
                    "Sid": "AllowMWAAVPCEndpoints",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateVpcEndpoint",
                        "ec2:DeleteVpcEndpoint",
                        "ec2:DescribeVpcEndpoints",
                        "ec2:DescribeVpcEndpointServices",
                        "ec2:ModifyVpcEndpoint",
                    ],
                    "Resource": "*"
                }

            ]
        }


    
    def attach_mwaa_group_prereqs_via_policy_maker(self, group_name):
        """
        Generates managed prereq policy and attaches it
        to the TEAM IAM GROUP.
        """

        policy_name = "MWAA-SageMaker-DataZone-GROUP-Prereqs"
        policy_desc = "Required permissions for MWAA + SageMaker Studio + DataZone (Group Scoped)"

        pol_doc = self.policy_mwaa_group_prereqs()

        arn = self.create_or_update_policy(
            policy_name=policy_name,
            policy_document=pol_doc,
            description=policy_desc
        )

        self.attach_policy_to_group(
            policy_arn=arn,
            group_name=group_name
        )

        print(f"✅ Attached MWAA/SageMaker/DataZone prereqs to GROUP: {group_name}")




    # =============================
    # ATTACH HELPERS
    # =============================

    def attach_policy_to_group(self, policy_arn, group_name):
        try:
            self.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
            print(f"🔗 Attached {policy_arn} → {group_name}")
        except Exception as e:
            print(f"⚠ Could not attach to group: {e}")


    def attach_policy_to_role(self, policy_arn, role_name):
        try:
            self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            print(f"🔗 Attached {policy_arn} → {role_name}")
        except Exception as e:
            print(f"⚠ Could not attach to role: {e}")
