import boto3
import botocore


class AWSGroupProvisioner:

    # =============================
    # INIT
    # =============================
    def __init__(self, region="us-east-1"):
        self.region = region
        self.iam = boto3.client("iam", region_name=region)

    # =============================
    # EMAIL → IAM USERNAME
    # =============================
    @staticmethod
    def normalize_username(email):
        """
        Converts email to IAM-safe username:
        john.doe@x.com → john_doe
        """
        return email.split("@")[0].replace(".", "_").replace("-", "_")

    # =============================
    # CREATE IAM GROUP (IDEMPOTENT)
    # =============================
    def create_group_if_missing(self, group_name):
        try:
            self.iam.get_group(GroupName=group_name)
            print(f"✔ Group exists: {group_name}")
        except self.iam.exceptions.NoSuchEntityException:
            print(f"➕ Creating group: {group_name}")
            self.iam.create_group(GroupName=group_name)

    # =============================
    # CREATE IAM USER (IDEMPOTENT)
    # =============================
    def create_user_if_missing(self, username):
        try:
            self.iam.get_user(UserName=username)
            print(f"✔ User exists: {username}")
        except self.iam.exceptions.NoSuchEntityException:
            print(f"➕ Creating user: {username}")
            self.iam.create_user(UserName=username)

    # =============================
    # ADD USER TO GROUP (IDEMPOTENT)
    # =============================
    def add_user_to_group(self, username, group_name):
        try:
            self.iam.add_user_to_group(
                UserName=username,
                GroupName=group_name
            )
            print(f"👥 Added {username} → {group_name}")
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                print(f"✔ {username} already in {group_name}")
            else:
                raise

    # =============================
    # ENSURE CONSOLE LOGIN PROFILE
    # =============================
    def ensure_login_profile(self, username, temp_password="Temp123!Pass"):
        """
        Creates a console login profile only if missing.
        Forces password reset on first login.
        """
        try:
            self.iam.get_login_profile(UserName=username)
            print(f"✔ Login profile exists: {username}")
        except self.iam.exceptions.NoSuchEntityException:
            print(f"🔐 Creating login profile for {username}")
            self.iam.create_login_profile(
                UserName=username,
                Password=temp_password,
                PasswordResetRequired=True
            )

    # =============================
    # MAIN ORCHESTRATOR
    # =============================
    def provision_all_users(self, team_members_map, create_console_login=False):
        """
        team_members_map = {
            "DE_27_Team11": ["user1@duke.edu", "user2@duke.edu"]
        }
        """

        for group_name, user_list in team_members_map.items():

            print("\n====================================================")
            print(f"🚀 Processing group: {group_name}")
            print("====================================================")

            # Ensure team group exists
            self.create_group_if_missing(group_name)

            for email in user_list:
                username = self.normalize_username(email)

                print(f"\n➡ Processing user: {email}  →  {username}")

                # Create IAM user if missing
                self.create_user_if_missing(username)

                # Add user to group
                self.add_user_to_group(username, group_name)

                # Optional console login
                if create_console_login:
                    self.ensure_login_profile(username)

            print(f"\n🎉 Finished team: {group_name}")
