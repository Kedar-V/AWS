import boto3
import os
import json
from botocore.exceptions import ClientError

"""
Networking + Launch Template Manager
(LaunchTemplate kept here per your current structure)
"""

class AWSNetworkManager:

	# ================================================================
	# INIT
	# ================================================================
	def __init__(self, region="us-east-1"):
		self.region = region
		self.ec2 = boto3.client("ec2", region_name=region)
		self.iam = boto3.client("iam", region_name=region)
		self.rds = boto3.client("rds", region_name=region)
		self.sts = boto3.client("sts", region_name=region)

		self.account_id = self.sts.get_caller_identity()["Account"]

		# ---------------- SHARED CONFIG ----------------
		self.SHARED_VPC_CIDR = "10.0.0.0/16"
		self.PUBLIC_SUBNET_CIDR = "10.0.1.0/24"
		self.PRIVATE_SUBNET_CIDR_1 = "10.0.2.0/24"
		self.PRIVATE_SUBNET_CIDR_2 = "10.0.3.0/24"

		self.ADMIN_IP = "0.0.0.0/0"
		self.AMI_ID = "ami-0cae6d6fe6048ca2c"
		self.INSTANCE_TYPE = "t3.micro"


	# ================================================================
	# TEAM NAME NORMALIZATION (SINGLE SOURCE OF TRUTH)
	# ================================================================
	@staticmethod
	def normalize_team(team_name: str) -> str:
		"""
		DE_27_Team7 -> de-27-team7  (for AWS resources)
		"""
		return team_name.lower().replace("_", "-")


	@staticmethod
	def iam_group_from_team(team_name: str) -> str:
		"""
		IAM group always remains:
		DE_27_Team7
		"""
		return team_name


	# ================================================================
	# TAGGING
	# ================================================================
	def tag(self, resource_id, name, project="shared-vpc"):
		try:
			self.ec2.create_tags(
				Resources=[resource_id],
				Tags=[
					{"Key": "Name", "Value": name},
					{"Key": "Project", "Value": project},
					{"Key": "ManagedBy", "Value": "AutomationScript"}
				]
			)
		except Exception:
			pass


	# ================================================================
	# VPC
	# ================================================================
	def get_or_create_shared_vpc(self):
		vpcs = self.ec2.describe_vpcs(
			Filters=[{"Name": "cidr-block", "Values": [self.SHARED_VPC_CIDR]}]
		)["Vpcs"]

		if vpcs:
			vpc = vpcs[0]["VpcId"]
			print("🟢 Shared VPC exists:", vpc)
		else:
			vpc = self.ec2.create_vpc(CidrBlock=self.SHARED_VPC_CIDR)["Vpc"]["VpcId"]
			print("🟢 Created Shared VPC:", vpc)

		self.tag(vpc, "shared-vpc")
		self.ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsSupport={'Value': True})
		self.ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={'Value': True})
		return vpc


	# ================================================================
	# IGW
	# ================================================================
	def get_or_create_shared_igw(self, vpc_id):
		igws = self.ec2.describe_internet_gateways(
			Filters=[{"Name": "tag:Name", "Values": ["shared-igw"]}]
		)["InternetGateways"]

		if igws:
			igw = igws[0]["InternetGatewayId"]
			print("🌐 Shared IGW exists:", igw)
		else:
			igw = self.ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
			self.ec2.attach_internet_gateway(VpcId=vpc_id, InternetGatewayId=igw)
			self.tag(igw, "shared-igw")
			print("🌐 Created Shared IGW:", igw)

		return igw


	# ================================================================
	# SUBNET
	# ================================================================
	def get_existing_or_create_subnet(self, cidr, name, vpc_id, availability_zone=None, public=False):
		subs = self.ec2.describe_subnets(
			Filters=[{"Name": "cidr-block", "Values": [cidr]}]
		)["Subnets"]

		if subs:
			sn = subs[0]["SubnetId"]
			print(f"🟨 Reusing subnet {name}: {sn}")
			return sn

		params = dict(VpcId=vpc_id, CidrBlock=cidr)
		if availability_zone:
			params["AvailabilityZone"] = availability_zone

		sn = self.ec2.create_subnet(**params)["Subnet"]["SubnetId"]
		print(f"🟨 Created subnet {name}: {sn}")

		if public:
			self.ec2.modify_subnet_attribute(SubnetId=sn, MapPublicIpOnLaunch={'Value': True})

		self.tag(sn, name)
		return sn


	# ================================================================
	# ROUTE TABLE
	# ================================================================
	def get_or_create_rtb(self, vpc, igw, public_subnet):
		rtbs = self.ec2.describe_route_tables(
			Filters=[{"Name": "tag:Name", "Values": ["shared-public-rt"]}]
		)["RouteTables"]

		if rtbs:
			rt = rtbs[0]["RouteTableId"]
		else:
			rt = self.ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]

		self.tag(rt, "shared-public-rt")

		try:
			self.ec2.create_route(
				RouteTableId=rt,
				DestinationCidrBlock="0.0.0.0/0",
				GatewayId=igw
			)
		except Exception:
			pass

		try:
			self.ec2.associate_route_table(RouteTableId=rt, SubnetId=public_subnet)
		except Exception:
			pass

		return rt


	# ================================================================
	# RDS SUBNET GROUP
	# ================================================================
	def create_shared_rds_subnet_group(self, sub1, sub2):
		name = "shared-rds-subnet-group"
		try:
			self.rds.describe_db_subnet_groups(DBSubnetGroupName=name)
			return name
		except Exception:
			pass

		self.rds.create_db_subnet_group(
			DBSubnetGroupName=name,
			DBSubnetGroupDescription="Shared RDS Subnet Group",
			SubnetIds=[sub1, sub2],
			Tags=[{"Key": "Name", "Value": name}]
		)

		return name


	# ================================================================
	# TEAM KEYPAIR
	# ================================================================
	def create_team_keypair(self, team_name):
		team = self.normalize_team(team_name)

		exists = self.ec2.describe_key_pairs(
			Filters=[{"Name": "key-name", "Values": [team]}]
		)["KeyPairs"]

		if exists:
			return team

		kp = self.ec2.create_key_pair(KeyName=team, KeyType="ed25519")
		fname = f"{team}.pem"

		with open(fname, "w") as f:
			f.write(kp["KeyMaterial"])

		os.chmod(fname, 0o400)
		self.tag(kp["KeyPairId"], f"{team}-key", team)
		return team


	# ================================================================
	# TEAM SECURITY GROUP
	# ================================================================
	def create_team_sg(self, team_name, vpc_id):
		team = self.normalize_team(team_name)
		sg_name = f"{team}-sg"

		sgs = self.ec2.describe_security_groups(
			Filters=[{"Name": "group-name", "Values": [sg_name]}]
		)["SecurityGroups"]

		if sgs:
			sg = sgs[0]["GroupId"]
		else:
			sg = self.ec2.create_security_group(
				GroupName=sg_name,
				Description=f"SG for {team_name}",
				VpcId=vpc_id
			)["GroupId"]

		self.tag(sg, sg_name, team)

		try:
			self.ec2.authorize_security_group_ingress(
				GroupId=sg,
				IpPermissions=[{
					"IpProtocol": "tcp",
					"FromPort": 22,
					"ToPort": 22,
					"IpRanges": [{"CidrIp": self.ADMIN_IP}]
				}]
			)
		except Exception:
			pass

		return sg


	# ================================================================
	# LAUNCH TEMPLATE
	# ================================================================
	def create_or_update_launch_template(self, team_name, subnet_id, sg_id):
		team = self.normalize_team(team_name)

		template_data = {
			"ImageId": self.AMI_ID,
			"InstanceType": self.INSTANCE_TYPE,
			"KeyName": team,
			"NetworkInterfaces": [{
				"DeviceIndex": 0,
				"SubnetId": subnet_id,
				"Groups": [sg_id],
				"AssociatePublicIpAddress": True
			}],
			"TagSpecifications": [
				{
					"ResourceType": "instance",
					"Tags": [
						{"Key": "Team", "Value": team_name},
						{"Key": "ManagedBy", "Value": "LaunchTemplate"}
					]
				},
				{
					"ResourceType": "volume",
					"Tags": [
						{"Key": "Team", "Value": team_name},
						{"Key": "ManagedBy", "Value": "LaunchTemplate"}
					]
				}
			]
		}

		try:
			resp = self.ec2.create_launch_template(
				LaunchTemplateName=team,
				LaunchTemplateData=template_data
			)
			return resp["LaunchTemplate"]["LaunchTemplateId"]

		except ClientError:
			resp = self.ec2.create_launch_template_version(
				LaunchTemplateName=team,
				LaunchTemplateData=template_data
			)

			version = resp["LaunchTemplateVersion"]["VersionNumber"]
			lt_id = resp["LaunchTemplateVersion"]["LaunchTemplateId"]

			self.ec2.modify_launch_template(
				LaunchTemplateName=team,
				DefaultVersion=str(version)
			)

			return lt_id


	# ================================================================
	# IAM VISIBILITY POLICIES (SAFE GROUP ATTACH)
	# ================================================================
	def _create_or_update_policy(self, name, doc):
		arn = f"arn:aws:iam::{self.account_id}:policy/{name}"

		try:
			self.iam.create_policy(
				PolicyName=name,
				PolicyDocument=json.dumps(doc)
			)
			print(f"✅ Created policy: {name}")

		except ClientError as e:
			if e.response["Error"]["Code"] != "EntityAlreadyExists":
				raise

			print(f"🔄 Policy exists, rotating: {name}")

			# --- LIST ALL VERSIONS ---
			versions = self.iam.list_policy_versions(PolicyArn=arn)["Versions"]

			non_default = sorted(
				[v for v in versions if not v["IsDefaultVersion"]],
				key=lambda x: x["CreateDate"]
			)

			# --- DELETE OLDEST IF AT LIMIT ---
			if len(non_default) >= 4:
				oldest = non_default[0]["VersionId"]
				print(f"🧹 Deleting old version: {oldest}")
				self.iam.delete_policy_version(
					PolicyArn=arn,
					VersionId=oldest
				)

			# --- CREATE NEW VERSION ---
			self.iam.create_policy_version(
				PolicyArn=arn,
				PolicyDocument=json.dumps(doc),
				SetAsDefault=True
			)

			print(f"✅ Updated policy: {name}")

		return arn



	def attach_team_lt_policy(self, team_name):
		team = self.normalize_team(team_name)
		group_name = self.iam_group_from_team(team_name)

		policy_name = f"{team}-LTVisibility"

		policy_doc = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": [
					"ec2:DescribeLaunchTemplates",
					"ec2:DescribeLaunchTemplateVersions"
				],
				"Resource": "*"
			}]
		}

		arn = self._create_or_update_policy(policy_name, policy_doc)
		self.iam.attach_group_policy(GroupName=group_name, PolicyArn=arn)


	def attach_team_rds_policy(self, team_name):
		team = self.normalize_team(team_name)
		group_name = self.iam_group_from_team(team_name)

		policy_name = f"{team}-RDSVisibility"

		policy_doc = {
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Action": ["rds:Describe*"],
				"Resource": "*"
			}]
		}

		arn = self._create_or_update_policy(policy_name, policy_doc)
		self.iam.attach_group_policy(GroupName=group_name, PolicyArn=arn)
