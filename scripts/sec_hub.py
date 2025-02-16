import boto3
import json
import csv
import argparse
from datetime import datetime

def get_filtered_findings(region, profile=None, max_results=1000):
    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    securityhub = session.client('securityhub')

    findings = []
    next_token = None
    filters = {
        "GeneratorId": [{"Value": "cms.tenable", "Comparison": "PREFIX"}],
        "ProductFields": [{"Key": "Type", "Value": "active", "Comparison": "EQUALS"}],
        "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
    }

    while True:
        kwargs = {
            "Filters": filters,
            "MaxResults": 100
        }

        if next_token:
            kwargs["NextToken"] = next_token

        response = securityhub.get_findings(**kwargs)
        findings.extend(response.get('Findings', []))
        next_token = response.get('NextToken')

        if not next_token:
            break

        if max_results > 0 and len(findings) >= max_results:
            break

    return findings if max_results == 0 else findings[:max_results]

def extract_finding_details(findings):
    extracted_findings = []
    
    for finding in findings:
        notes_text = finding.get('Note', {}).get('Text', '')
        
        resources = finding.get('Resources', [])
        resource_arns = [r.get('Id', '') for r in resources]
        resource_ips = []
        for resource in resources:
            details = resource.get('Details', {})
            aws_ec2_instance = details.get('AwsEc2Instance', {})
            if 'IpV4Addresses' in aws_ec2_instance:
                resource_ips.extend(aws_ec2_instance['IpV4Addresses'])
        
        finding_detail = {
            'Title': finding.get('Title', ''),
            'Description': finding.get('Description', ''),
            'CreatedAt': finding.get('CreatedAt', ''),
            'UpdatedAt': finding.get('UpdatedAt', ''),
            'Notes': notes_text,
            'ResourceARNs': ' | '.join(resource_arns),
            'ResourceIPs': ' | '.join(resource_ips),
            'FindingId': finding.get('Id', ''),
            'Severity': finding.get('Severity', {}).get('Label', '')
        }
        extracted_findings.append(finding_detail)
    
    return extracted_findings

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrieve filtered AWS Security Hub findings.")
    parser.add_argument("--region", required=True, help="AWS region (e.g., us-east-1)")
    parser.add_argument("--profile", help="AWS CLI profile name (optional)")
    parser.add_argument("--max-results", type=int, default=1000, help="Maximum number of results to fetch (0 for all)")

    args = parser.parse_args()

    findings = get_filtered_findings(args.region, args.profile, args.max_results)
    
    findings_details = extract_finding_details(findings)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_filename = f"securityhub_findings_{args.region}_{timestamp}.json"
    with open(json_filename, "w") as f:
        json.dump(findings_details, f, indent=4)

    csv_filename = f"securityhub_findings_{args.region}_{timestamp}.csv"
    if findings_details:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = findings_details[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings_details)

    print(f"Retrieved {len(findings)} filtered findings.")
    print(f"JSON data saved to {json_filename}")
    print(f"CSV data saved to {csv_filename}")