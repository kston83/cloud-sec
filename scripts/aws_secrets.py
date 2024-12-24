import boto3
import datetime
import json
import argparse


def get_aws_session(profile_name=None, region_name=None):
    """Create a boto3 session for a given profile and region."""
    return boto3.Session(profile_name=profile_name, region_name=region_name)


def list_all_regions():
    """Retrieve a list of all available AWS regions."""
    ec2_client = boto3.client('ec2')
    regions = ec2_client.describe_regions()['Regions']
    return [region['RegionName'] for region in regions]


def create_baseline_inventory(secrets_client):
    """Create a baseline inventory of secrets."""
    secrets = []
    paginator = secrets_client.get_paginator('list_secrets')

    for page in paginator.paginate():
        for secret in page['SecretList']:
            secret_details = {
                "Name": secret['Name'],
                "SecretId": secret['ARN'],
                "LastRotated": secret.get('LastChangedDate', "Never Rotated"),
                "CreatedDate": secret.get('CreatedDate', "Unknown"),
            }
            secrets.append(secret_details)

    print("Baseline inventory retrieved.")
    return secrets


def get_rotation_events(cloudtrail_client, start_days_back=60):
    """Retrieve RotateSecret events from CloudTrail."""
    start_time = datetime.datetime.utcnow() - datetime.timedelta(days=start_days_back)
    end_time = datetime.datetime.utcnow()

    events = []
    paginator = cloudtrail_client.get_paginator('lookup_events')

    for page in paginator.paginate(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': 'RotateSecret'
            }
        ],
        StartTime=start_time,
        EndTime=end_time
    ):
        for event in page['Events']:
            event_details = json.loads(event['CloudTrailEvent'])
            events.append({
                "SecretId": event_details.get("requestParameters", {}).get("secretId", "Unknown"),
                "EventTime": event['EventTime'],
                "Username": event['Username'],
                "Region": event['AwsRegion'],
            })

    print(f"Retrieved {len(events)} RotateSecret events.")
    return events


def validate_secret_rotation(baseline, events):
    """Validate rotation of secrets against the baseline."""
    rotated_secrets = {event["SecretId"] for event in events}
    validation_results = []

    for secret in baseline:
        is_rotated = "Yes" if secret["SecretId"] in rotated_secrets else "No"
        validation_results.append({
            "Name": secret["Name"],
            "SecretId": secret["SecretId"],
            "LastRotated": secret["LastRotated"],
            "IsRotatedInLast60Days": is_rotated
        })

    return validation_results


def generate_markdown_report(baseline, validation_results, rotation_events, profile_name, output_file="report.md"):
    """Generate a markdown report."""
    with open(output_file, 'w') as mdfile:
        # Write header with the profile name
        mdfile.write(f"# Secrets Inventory and Rotation Report for Profile: {profile_name}\n\n")

        # Baseline Inventory
        mdfile.write("## Baseline Inventory\n\n")
        mdfile.write("| Name | SecretId | LastRotated | CreatedDate |\n")
        mdfile.write("|------|----------|-------------|-------------|\n")
        for secret in baseline:
            mdfile.write(f"| {secret['Name']} | {secret['SecretId']} | {secret['LastRotated']} | {secret['CreatedDate']} |\n")

        # Validation Results
        mdfile.write("\n## Validation Results\n\n")
        mdfile.write("| Name | SecretId | LastRotated | IsRotatedInLast60Days |\n")
        mdfile.write("|------|----------|-------------|-----------------------|\n")
        for result in validation_results:
            mdfile.write(f"| {result['Name']} | {result['SecretId']} | {result['LastRotated']} | {result['IsRotatedInLast60Days']} |\n")

        # Rotation Events
        mdfile.write("\n## Rotation Events\n\n")
        mdfile.write("| SecretId | EventTime | Username | Region |\n")
        mdfile.write("|----------|-----------|----------|--------|\n")
        for event in rotation_events:
            mdfile.write(f"| {event['SecretId']} | {event['EventTime']} | {event['Username']} | {event['Region']} |\n")

    print(f"Markdown report generated: {output_file}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Secrets Inventory and Rotation Report")
    parser.add_argument("--profile", help="AWS CLI profile to use", required=False, default="default")
    parser.add_argument("--region", help="AWS region to use", required=False, default="us-east-1")
    args = parser.parse_args()

    profile = args.profile
    region = args.region

    print(f"Processing profile: {profile}, region: {region or 'all regions'}")

    # Determine regions to process
    regions = [region] if region else list_all_regions()

    all_baselines = []
    all_rotation_events = []

    for region in regions:
        print(f"Processing region: {region}")

        # Initialize AWS session
        session = get_aws_session(profile_name=profile, region_name=region)
        secrets_client = session.client('secretsmanager')
        cloudtrail_client = session.client('cloudtrail')

        # Generate baseline inventory for this region
        baseline = create_baseline_inventory(secrets_client)
        all_baselines.extend(baseline)

        # Get rotation events from CloudTrail for this region
        rotation_events = get_rotation_events(cloudtrail_client, start_days_back=60)
        all_rotation_events.extend(rotation_events)

    # Validate rotation across all regions
    validation_results = validate_secret_rotation(all_baselines, all_rotation_events)

    # Generate a consolidated markdown report with the profile name in the title
    output_file = f"{profile}_secrets_report.md"
    generate_markdown_report(all_baselines, validation_results, all_rotation_events, profile, output_file)


if __name__ == "__main__":
    main()

