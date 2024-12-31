import boto3
import json
import argparse
from datetime import datetime, timezone

## Script to generate a report of IAM users and access keys

def get_aws_session(profile_name=None):
    """Create a boto3 session for a given profile."""
    return boto3.Session(profile_name=profile_name)

def list_iam_users(iam_client):
    """Retrieve a list of IAM users and their details."""
    users = []
    paginator = iam_client.get_paginator('list_users')

    for page in paginator.paginate():
        for user in page['Users']:
            user_details = {
                "UserName": user['UserName'],
                "UserId": user['UserId'],
                "Arn": user['Arn'],
                "CreateDate": user['CreateDate'].strftime("%Y-%m-%d %H:%M:%S"),
                "PasswordLastUsed": user.get('PasswordLastUsed', "Never Used")
            }

            # Retrieve access key information
            access_keys = iam_client.list_access_keys(UserName=user['UserName'])
            user_details["AccessKeys"] = [
                {
                    "AccessKeyId": key['AccessKeyId'],
                    "Status": key['Status'],
                    "CreateDate": key['CreateDate'].strftime("%Y-%m-%d %H:%M:%S"),
                    "AgeInDays": (datetime.now(timezone.utc) - key['CreateDate']).days,
                    "LastUsed": iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId']).get('AccessKeyLastUsed', {}).get('LastUsedDate', "Never Used")
                }
                for key in access_keys.get('AccessKeyMetadata', [])
            ]

            users.append(user_details)

    print(f"Retrieved {len(users)} IAM users.")
    return users

def generate_markdown_report(users, profile_name, output_file="iam_users_report.md"):
    """Generate a markdown report."""
    with open(output_file, 'w') as mdfile:
        # Write header with the profile name
        mdfile.write(f"# IAM Users Report for Profile: {profile_name}\n\n")

        # User Details
        mdfile.write("## IAM Users\n\n")
        mdfile.write("| UserName | UserId | Arn | CreateDate | PasswordLastUsed |\n")
        mdfile.write("|----------|--------|-----|------------|------------------|\n")
        for user in users:
            mdfile.write(f"| {user['UserName']} | {user['UserId']} | {user['Arn']} | {user['CreateDate']} | {user['PasswordLastUsed']} |\n")

        # Access Key Details
        mdfile.write("\n## IAM Access Keys\n\n")
        mdfile.write("| UserName | AccessKeyId | Status | CreateDate | AgeInDays | LastUsed |\n")
        mdfile.write("|----------|-------------|--------|------------|-----------|----------|\n")
        for user in users:
            for key in user['AccessKeys']:
                last_used = key['LastUsed'] if isinstance(key['LastUsed'], str) else key['LastUsed'].strftime("%Y-%m-%d %H:%M:%S")
                mdfile.write(f"| {user['UserName']} | {key['AccessKeyId']} | {key['Status']} | {key['CreateDate']} | {key['AgeInDays']} | {last_used} |\n")

    print(f"Markdown report generated: {output_file}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="IAM Users Report")
    parser.add_argument("--profile", help="AWS CLI profile to use", required=False, default="default")
    args = parser.parse_args()

    profile = args.profile

    print(f"Processing profile: {profile}")

    # Initialize AWS session
    session = get_aws_session(profile_name=profile)
    iam_client = session.client('iam')

    # List IAM users
    users = list_iam_users(iam_client)

    # Generate a markdown report with the profile name in the title
    output_file = f"{profile}_iam_users_report.md"
    generate_markdown_report(users, profile, output_file)

if __name__ == "__main__":
    main()
