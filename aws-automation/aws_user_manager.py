import boto3
import csv
import random
import string
import botocore


class AWSUserManager:

    # =============================
    # INIT
    # =============================
    def __init__(self, region="us-east-1"):
        self.region = region
        self.iam = boto3.client("iam", region_name=region)
        self.sts = boto3.client("sts", region_name=region)
        self.account_id = self.sts.get_caller_identity()["Account"]


    # =============================
    # PASSWORD GENERATOR
    # =============================
    def generate_password(self, length=16):
        upper = random.choice(string.ascii_uppercase)
        lower = random.choice(string.ascii_lowercase)
        digit = random.choice(string.digits)
        symbol = random.choice("!@#$%^&*()-_=+[]{}?")

        remaining = length - 4
        pool = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}?"

        random_chars = [random.choice(pool) for _ in range(remaining)]
        password_list = [upper, lower, digit, symbol] + random_chars
        random.shuffle(password_list)

        return "".join(password_list)


    # =============================
    # FULL USER DELETION
    # =============================
    def delete_user_if_exists(self, username):
        try:
            self.iam.get_user(UserName=username)
        except self.iam.exceptions.NoSuchEntityException:
            return

        print(f"🗑 Deleting existing user: {username}")

        # Remove from groups
        groups = self.iam.list_groups_for_user(UserName=username)["Groups"]
        for g in groups:
            self.iam.remove_user_from_group(
                UserName=username,
                GroupName=g["GroupName"]
            )

        # Delete login profile
        try:
            self.iam.delete_login_profile(UserName=username)
        except self.iam.exceptions.NoSuchEntityException:
            pass

        # Delete access keys
        keys = self.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for k in keys:
            self.iam.delete_access_key(
                UserName=username,
                AccessKeyId=k["AccessKeyId"]
            )

        # Delete inline policies
        policies = self.iam.list_user_policies(UserName=username)["PolicyNames"]
        for p in policies:
            self.iam.delete_user_policy(
                UserName=username,
                PolicyName=p
            )

        # Detach managed policies
        attached = self.iam.list_attached_user_policies(
            UserName=username
        )["AttachedPolicies"]
        for p in attached:
            self.iam.detach_user_policy(
                UserName=username,
                PolicyArn=p["PolicyArn"]
            )

        # Delete MFA devices
        mfas = self.iam.list_mfa_devices(UserName=username)["MFADevices"]
        for m in mfas:
            self.iam.deactivate_mfa_device(
                UserName=username,
                SerialNumber=m["SerialNumber"]
            )
            self.iam.delete_virtual_mfa_device(
                SerialNumber=m["SerialNumber"]
            )

        # Delete user
        self.iam.delete_user(UserName=username)
        print(f"✔ User deleted: {username}")


    # =============================
    # CREATE FRESH USER
    # =============================
    def create_fresh_user(self, username, group_name):
        print(f"\n👤 Creating IAM user: {username}")

        # Create user
        self.iam.create_user(UserName=username)

        # Attach to group
        self.iam.add_user_to_group(
            UserName=username,
            GroupName=group_name
        )

        # Create console password
        password = self.generate_password()
        self.iam.create_login_profile(
            UserName=username,
            Password=password,
            PasswordResetRequired=True
        )
        print("🔐 Console password created")

        # Create access key
        key = self.iam.create_access_key(UserName=username)["AccessKey"]
        access_key_id = key["AccessKeyId"]
        secret_key = key["SecretAccessKey"]

        print("🔑 Access key created")

        return password, access_key_id, secret_key


    # =============================
    # EXPORT TO CSV
    # =============================
    def export_credentials(self, creds, filename="team_user_credentials.csv"):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Username",
                "AWS Console Login URL",
                "Temporary Password",
                "Access Key ID",
                "Secret Access Key"
            ])

            login_url = f"https://{self.account_id}.signin.aws.amazon.com/console"

            for row in creds:
                writer.writerow([
                    row["username"],
                    login_url,
                    row["password"],
                    row["access_key"],
                    row["secret_key"]
                ])

        print(f"\n📄 Saved credentials to {filename}")


    # =============================
    # TEAM ORCHESTRATOR
    # =============================
    def recreate_team_users(self, team_members_map, output_file="team_user_credentials.csv"):
        """
        team_members_map = {
            "DE_27_Team11": ["Alice Brown", "Bob Smith"],
            "DE_27_Team12": ["Carol Lee"]
        }
        """

        all_credentials = []

        for group_name, members in team_members_map.items():
            print(f"\n====== Processing Team Group: {group_name} ======\n")

            for member in members:
                username = member.lower().replace(" ", "_")

                # Full reset
                self.delete_user_if_exists(username)

                # Fresh creation
                password, access_key_id, secret_key = self.create_fresh_user(
                    username, group_name
                )

                all_credentials.append({
                    "username": username,
                    "password": password,
                    "access_key": access_key_id,
                    "secret_key": secret_key
                })

        self.export_credentials(all_credentials, filename=output_file)
        return all_credentials
