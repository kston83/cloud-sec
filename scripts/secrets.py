import argparse
import boto3
import datetime
import json
import os
import sys
import logging
import yaml
from collections import defaultdict

# =====================================================
# Setup Logging
# =====================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# =====================================================
# Hard-coded Exclusion List (for false positives)
# =====================================================

# Any secret whose name starts with one of these prefixes will be excluded.
EXCLUSION_PREFIXES = [
    "cms-cloud-"
]

def is_excluded_secret(secret_name, exclusion_prefixes=EXCLUSION_PREFIXES):
    """
    Return True if the secret_name starts with any of the provided exclusion_prefixes.
    """
    for prefix in exclusion_prefixes:
        if secret_name.startswith(prefix):
            return True
    return False

# =====================================================
# Configuration Loader
# =====================================================

def load_config(config_path="config.yaml"):
    """Load configuration from a YAML file."""
    try:
        with open(config_path, 'r') as stream:
            config = yaml.safe_load(stream)
            logging.info("Configuration loaded successfully from %s.", config_path)
            return config
    except FileNotFoundError:
        logging.error("Configuration file '%s' not found.", config_path)
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error("Error parsing YAML configuration: %s", e)
        sys.exit(1)

# =====================================================
# Command-Line Argument Parsing
# =====================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Scan AWS Secrets Manager rotation status.")
    parser.add_argument("--project", help="Optional project name to scan. If omitted, scan all projects.")
    return parser.parse_args()

# =====================================================
# Helper Functions
# =====================================================

def get_aws_session(profile_name=None, region_name=None):
    """Create a boto3 session for a given profile and region."""
    return boto3.Session(profile_name=profile_name, region_name=region_name)

def format_datetime(dt):
    """Helper function to format datetime objects consistently."""
    if isinstance(dt, datetime.datetime):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt)

# =====================================================
# AWS Secrets and CloudTrail Functions
# =====================================================

def create_baseline_inventory(secrets_client):
    """Create a baseline inventory of secrets with days since last rotation."""
    secrets = []
    paginator = secrets_client.get_paginator('list_secrets')
    current_time = datetime.datetime.now(datetime.timezone.utc)

    for page in paginator.paginate():
        for secret in page.get('SecretList', []):
            secret_name = secret.get('Name', 'Unknown')
            # Skip secret if it matches an exclusion prefix
            if is_excluded_secret(secret_name):
                continue

            # Use LastChangedDate if available, otherwise fallback to CreatedDate
            last_rotated = secret.get('LastChangedDate', secret.get('CreatedDate'))
            days_since_rotation = None
            if last_rotated:
                days_since_rotation = (current_time - last_rotated).days

            secret_details = {
                "Name": secret_name,
                "SecretId": secret.get('ARN', 'Unknown'),
                "LastRotated": last_rotated,
                "CreatedDate": secret.get('CreatedDate', "Unknown"),
                "DaysSinceRotation": days_since_rotation
            }
            secrets.append(secret_details)

    logging.info("Baseline inventory retrieved with %d secrets (excluding false positives).", len(secrets))
    return secrets

def get_rotation_events(cloudtrail_client, start_days_back=60):
    """Retrieve RotateSecret events from CloudTrail."""
    start_time = datetime.datetime.utcnow() - datetime.timedelta(days=start_days_back)
    end_time = datetime.datetime.utcnow()

    events = []
    paginator = cloudtrail_client.get_paginator('lookup_events')

    for page in paginator.paginate(
        LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'RotateSecret'}],
        StartTime=start_time,
        EndTime=end_time
    ):
        for event in page.get('Events', []):
            try:
                event_details = json.loads(event['CloudTrailEvent'])
            except json.JSONDecodeError:
                logging.warning("Failed to parse CloudTrail event: %s", event)
                continue

            events.append({
                "SecretId": event_details.get("requestParameters", {}).get("secretId", "Unknown"),
                "EventTime": event['EventTime'],
                "Username": event.get('Username', 'Unknown'),
                "Region": event.get('AwsRegion', 'Unknown'),
            })

    logging.info("Retrieved %d RotateSecret events.", len(events))
    return events

def validate_secret_rotation(baseline, events, rotation_threshold=60, warning_threshold=14):
    """
    Validate rotation of secrets against the baseline with expiry warnings.
    Returns:
      - validation_results: list of dicts with audit details.
      - approaching_expiry: list of dicts for secrets nearing expiry.
    """
    rotated_secrets = {event["SecretId"] for event in events}
    validation_results = []
    approaching_expiry = []

    for secret in baseline:
        days_since = secret.get("DaysSinceRotation") or 0
        days_until_expiry = rotation_threshold - days_since

        result = {
            "Name": secret["Name"],
            "SecretId": secret["SecretId"],
            "LastRotated": secret["LastRotated"],
            "CreatedDate": secret["CreatedDate"],
            "DaysSinceRotation": days_since,
            "DaysUntilExpiry": days_until_expiry,
            "IsRotatedInLast60Days": "Yes" if secret["SecretId"] in rotated_secrets else "No"
        }
        validation_results.append(result)

        # Check if approaching expiry (only if not already expired)
        if 0 < days_until_expiry <= warning_threshold:
            approaching_expiry.append(result)

    return validation_results, approaching_expiry

def create_report_directory(base_dir, project_name, profile, timestamp):
    """Create nested directory structure for reports."""
    project_dir = os.path.join(base_dir, project_name)
    os.makedirs(project_dir, exist_ok=True)

    profile_dir = os.path.join(project_dir, profile)
    os.makedirs(profile_dir, exist_ok=True)

    report_dir = os.path.join(profile_dir, timestamp)
    os.makedirs(report_dir, exist_ok=True)

    return report_dir

# =====================================================
# Report Generation Functions
# =====================================================

def generate_markdown_report(profile, region, baseline, validation_results, rotation_events, 
                             project_name, approaching_expiry, report_dir):
    """
    Generate a region-specific markdown report.
    The report shows expired secrets first, then secrets approaching expiry,
    followed by the complete baseline inventory and rotation events.
    """
    output_file = os.path.join(report_dir, f"{region}_report.md")

    # Determine expired secrets from validation results (DaysUntilExpiry <= 0)
    expired_secrets = [r for r in validation_results if r['DaysUntilExpiry'] <= 0]

    with open(output_file, 'w') as mdfile:
        # Header
        mdfile.write(f"# Secrets Inventory and Rotation Report\n")
        mdfile.write(f"**Profile:** {profile}  \n")
        mdfile.write(f"**Region:** {region}  \n")
        mdfile.write(f"**Project:** {project_name}  \n")
        mdfile.write(f"**Report Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Expired Secrets Section (first)
        mdfile.write("## 🔴 Expired Secrets\n\n")
        if expired_secrets:
            mdfile.write("| Name | SecretId | Last Rotated | Days Since Expiry |\n")
            mdfile.write("|------|----------|--------------|-------------------|\n")
            for secret in sorted(expired_secrets, key=lambda x: x['DaysUntilExpiry']):
                days_since_expiry = abs(secret['DaysUntilExpiry'])
                mdfile.write(
                    f"| {secret['Name']} | {secret['SecretId']} | {format_datetime(secret['LastRotated'])} | {days_since_expiry} |\n"
                )
            mdfile.write("\n")
        else:
            mdfile.write("*No expired secrets found.*\n\n")

        # Approaching Expiry Section (next)
        mdfile.write("## ⚠️ Secrets Approaching Expiry\n\n")
        if approaching_expiry:
            mdfile.write("| Name | SecretId | Last Rotated | Days Until Expiry |\n")
            mdfile.write("|------|----------|--------------|-------------------|\n")
            for secret in sorted(approaching_expiry, key=lambda x: x['DaysUntilExpiry']):
                mdfile.write(
                    f"| {secret['Name']} | {secret['SecretId']} | {format_datetime(secret['LastRotated'])} | {secret['DaysUntilExpiry']} |\n"
                )
            mdfile.write("\n")
        else:
            mdfile.write("*No secrets approaching expiry.*\n\n")

        # Baseline Inventory Section (all secrets)
        mdfile.write("## 📋 Baseline Inventory\n\n")
        mdfile.write("| Name | SecretId | Last Rotated | Days Since Rotation |\n")
        mdfile.write("|------|----------|--------------|---------------------|\n")
        for secret in baseline:
            mdfile.write(
                f"| {secret['Name']} | {secret['SecretId']} | {format_datetime(secret['LastRotated'])} | {secret['DaysSinceRotation']} |\n"
            )
        mdfile.write("\n")

        # Rotation Events Section
        mdfile.write("## 🔄 Rotation Events\n\n")
        mdfile.write("| SecretId | EventTime | Username | Region |\n")
        mdfile.write("|----------|-----------|----------|--------|\n")
        for event in rotation_events:
            mdfile.write(
                f"| {event['SecretId']} | {format_datetime(event['EventTime'])} | {event['Username']} | {event['Region']} |\n"
            )
        mdfile.write("\n")

    logging.info("Generated region report: %s", output_file)
    return output_file

def generate_project_summary(project_name, all_validation_results, all_approaching_expiry, base_dir):
    """
    Generate a comprehensive project-level summary report.
    The report shows expired secrets first, then those approaching expiry,
    followed by detailed statistics.
    """
    project_dir = os.path.join(base_dir, project_name)
    os.makedirs(project_dir, exist_ok=True)
    output_file = os.path.join(project_dir, f"project_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md")

    # Ensure each record has Environment and Region keys
    for rec in all_validation_results:
        rec.setdefault('Environment', 'Unknown')
        rec.setdefault('Region', 'Unknown')

    with open(output_file, 'w') as mdfile:
        mdfile.write(f"# Project Summary: {project_name}\n")
        mdfile.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Expired Secrets Section (first)
        mdfile.write("## 🔴 Expired Secrets\n\n")
        expired_secrets = [r for r in all_validation_results if r['DaysUntilExpiry'] <= 0]
        if expired_secrets:
            mdfile.write("| Environment | Secret Name | Last Rotated | Days Since Expiry | Region |\n")
            mdfile.write("|-------------|-------------|--------------|-------------------|--------|\n")
            for secret in sorted(expired_secrets, key=lambda x: x['DaysUntilExpiry']):
                days_since_expiry = abs(secret['DaysUntilExpiry'])
                mdfile.write(
                    f"| {secret['Environment']} | {secret['Name']} | {format_datetime(secret['LastRotated'])} | {days_since_expiry} | {secret['Region']} |\n"
                )
            mdfile.write("\n")
        else:
            mdfile.write("*No expired secrets detected.*\n\n")

        # Approaching Expiry Section (next)
        mdfile.write("## ⚠️ Secrets Approaching Expiry\n\n")
        all_approaching = []
        for env, region, secrets in all_approaching_expiry:
            for secret in secrets:
                secret_data = secret.copy()
                secret_data['Environment'] = env
                secret_data['Region'] = region
                all_approaching.append(secret_data)
        sorted_approaching = sorted(all_approaching, key=lambda x: x['DaysUntilExpiry'])
        if sorted_approaching:
            mdfile.write("| Environment | Secret Name | Last Rotated | Days Until Expiry | Region |\n")
            mdfile.write("|-------------|-------------|--------------|-------------------|--------|\n")
            for secret in sorted_approaching:
                mdfile.write(
                    f"| {secret['Environment']} | {secret['Name']} | {format_datetime(secret['LastRotated'])} | {secret['DaysUntilExpiry']} | {secret['Region']} |\n"
                )
            mdfile.write("\n")
        else:
            mdfile.write("*No secrets approaching expiry in the next 14 days.*\n\n")

        # Detailed Statistics Section
        mdfile.write("## 📊 Project Statistics\n\n")
        env_stats = defaultdict(lambda: {'total': 0, 'expired': 0, 'approaching': 0, 'healthy': 0})
        for secret in all_validation_results:
            env = secret['Environment']
            env_stats[env]['total'] += 1
            if secret['DaysUntilExpiry'] <= 0:
                env_stats[env]['expired'] += 1
            elif secret['DaysUntilExpiry'] <= 14:
                env_stats[env]['approaching'] += 1
            else:
                env_stats[env]['healthy'] += 1

        mdfile.write("### Environment Breakdown\n\n")
        mdfile.write("| Environment | Total Secrets | Healthy | Approaching Expiry | Expired |\n")
        mdfile.write("|-------------|---------------|---------|-------------------|---------|\n")
        for env, stats in sorted(env_stats.items()):
            mdfile.write(
                f"| {env} | {stats['total']} | {stats['healthy']} | {stats['approaching']} | {stats['expired']} |\n"
            )
        mdfile.write("\n")

        total_secrets = sum(stats['total'] for stats in env_stats.values())
        total_expired = sum(stats['expired'] for stats in env_stats.values())
        total_approaching = sum(stats['approaching'] for stats in env_stats.values())
        total_healthy = sum(stats['healthy'] for stats in env_stats.values())

        mdfile.write("### Overall Totals\n\n")
        mdfile.write(f"- Total Secrets: {total_secrets}\n")
        mdfile.write(f"- Healthy Secrets: {total_healthy} ({(total_healthy / total_secrets * 100):.1f}%)\n")
        mdfile.write(f"- Approaching Expiry: {total_approaching} ({(total_approaching / total_secrets * 100):.1f}%)\n")
        mdfile.write(f"- Expired: {total_expired} ({(total_expired / total_secrets * 100):.1f}%)\n")

    logging.info("Generated project summary report: %s", output_file)
    return output_file

# =====================================================
# Main Function
# =====================================================

def main():
    # Parse command-line arguments
    args = parse_args()

    # Load configuration from config.yaml
    config = load_config()

    # Get profiles, projects, and regions from configuration
    profiles = config.get('profiles', [])
    projects = config.get('projects', {})
    regions_config = config.get('regions', {})

    # If a project name is provided on the command line, filter profiles by that project.
    if args.project:
        filtered_profiles = []
        for profile in profiles:
            proj = projects.get(profile, "Unknown")
            if proj.lower() == args.project.lower():
                filtered_profiles.append(profile)
        if not filtered_profiles:
            logging.error("No profiles found for project '%s'.", args.project)
            sys.exit(1)
        profiles = filtered_profiles

    # Timestamp for report directories
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = "reports"

    # Dictionary to store project-level results
    project_data = defaultdict(lambda: {
        'validation_results': [],
        'approaching_expiry': []
    })

    # Process each profile from config
    for profile in profiles:
        project_name = projects.get(profile, "Unknown")
        regions = regions_config.get(profile, [])
        report_dir = create_report_directory(base_dir, project_name, profile, timestamp)

        for region in regions:
            logging.info("Processing profile: %s, region: %s, project: %s", profile, region, project_name)
            session = get_aws_session(profile_name=profile, region_name=region)
            secrets_client = session.client('secretsmanager')
            cloudtrail_client = session.client('cloudtrail')

            baseline = create_baseline_inventory(secrets_client)
            rotation_events = get_rotation_events(cloudtrail_client)
            validation_results, approaching_expiry = validate_secret_rotation(baseline, rotation_events)

            # Add environment and region info to each validation result
            for result in validation_results:
                result['Environment'] = profile
                result['Region'] = region

            project_data[project_name]['validation_results'].extend(validation_results)
            if approaching_expiry:
                project_data[project_name]['approaching_expiry'].append((profile, region, approaching_expiry))

            generate_markdown_report(
                profile, region, baseline, validation_results, rotation_events,
                project_name, approaching_expiry, report_dir
            )

    # Generate project-level summary reports
    for proj_name, data in project_data.items():
        generate_project_summary(
            proj_name,
            data['validation_results'],
            data['approaching_expiry'],
            base_dir
        )

if __name__ == "__main__":
    main()
