import boto3
import datetime
import json
import yaml
import os

## Script to generate a report of Secrets Manager secrets and rotation events

def load_config(config_path="config.yaml"):
    """Load configuration from a YAML file."""
    try:
        with open(config_path, 'r') as stream:
            config = yaml.safe_load(stream)
            print("Configuration loaded successfully.")
            return config
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_path}' not found.")
        exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML configuration: {e}")
        exit(1)

def get_aws_session(profile_name=None, region_name=None):
    """Create a boto3 session for a given profile and region."""
    return boto3.Session(profile_name=profile_name, region_name=region_name)

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

def generate_markdown_report(profile, region, baseline, validation_results, rotation_events, project_name, output_dir="reports"):
    """Generate a markdown report with a unique file name based on profile and region."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create a unique file name based on profile and region
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"{profile}_{region}_{timestamp}_report.md")

    with open(output_file, 'w') as mdfile:
        # Write header
        mdfile.write(f"# Secrets Inventory and Rotation Report\n")
        mdfile.write(f"**Profile**: {profile}\n")
        mdfile.write(f"**Region**: {region}\n")
        mdfile.write(f"**Project**: {project_name}\n\n")

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
    # Load configuration
    config = load_config()

    for profile in config.get('profiles', []):
        project_name = config.get('projects', {}).get(profile, "Unknown")
        regions = config.get('regions', {}).get(profile, [])

        for region in regions:
            print(f"Processing profile: {profile}, region: {region}, project: {project_name}")

            # Initialize AWS session
            session = get_aws_session(profile_name=profile, region_name=region)
            secrets_client = session.client('secretsmanager')
            cloudtrail_client = session.client('cloudtrail')

            # Generate baseline inventory for this region
            baseline = create_baseline_inventory(secrets_client)

            # Get rotation events from CloudTrail for this region
            rotation_events = get_rotation_events(cloudtrail_client, start_days_back=60)

            # Validate rotation
            validation_results = validate_secret_rotation(baseline, rotation_events)

            # Generate a markdown report
            generate_markdown_report(profile, region, baseline, validation_results, rotation_events, project_name)

if __name__ == "__main__":
    main()
