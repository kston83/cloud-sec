#!/usr/bin/env python3
import argparse
import subprocess
import json
import os
import csv
from datetime import datetime

# Define AWS resource commands
AWS_COMMANDS = {
    # Compute Resources
    "EC2 Instances": "aws ec2 describe-instances --query 'Reservations[].Instances[*].[InstanceId, InstanceType, State.Name, PrivateIpAddress, PublicIpAddress, VpcId, SubnetId, Tags[?Key==`Name`].Value | [0]]' --output json",
    "Auto Scaling Groups": "aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[*].[AutoScalingGroupName, MinSize, MaxSize, DesiredCapacity, VPCZoneIdentifier]' --output json",
    #"EC2 AMIs": "aws ec2 describe-images --owners self --query 'Images[*].[ImageId, Name, CreationDate, State]' --output json",
    
    # Database Resources
    "RDS Databases": "aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier, Engine, EngineVersion, DBInstanceClass, DBInstanceStatus, Endpoint.Address, MultiAZ]' --output json",
    "ElastiCache Clusters": "aws elasticache describe-cache-clusters --query 'CacheClusters[*].[CacheClusterId, Engine, CacheNodeType, CacheClusterStatus, NumCacheNodes]' --output json",
    "DynamoDB Tables": "aws dynamodb list-tables --output json",
    "Aurora Clusters": "aws rds describe-db-clusters --query 'DBClusters[*].[DBClusterIdentifier, Engine, EngineVersion, Status, MultiAZ]' --output json",
    
    # Container Services
    "ECS Clusters": "aws ecs list-clusters --query 'clusterArns' --output json",
    "ECS Services": "aws ecs list-services --query 'serviceArns' --output json",
    "ECS Task Definitions": "aws ecs list-task-definitions --query 'taskDefinitionArns' --output json",
    "EKS Clusters": "aws eks list-clusters --output json",
    
    # Serverless Resources
    "Lambda Functions": "aws lambda list-functions --query 'Functions[*].[FunctionName, Runtime, MemorySize, Timeout, LastModified]' --output json",
    "API Gateway REST APIs": "aws apigateway get-rest-apis --query 'items[*].[id, name, description]' --output json",
    "API Gateway HTTP APIs": "aws apigatewayv2 get-apis --query 'Items[*].[ApiId, Name, ProtocolType]' --output json",
    
    # Load Balancing/Networking
    "Load Balancers": "aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerName, DNSName, Type, Scheme, State.Code, VpcId]' --output json",
    "Target Groups": "aws elbv2 describe-target-groups --query 'TargetGroups[*].[TargetGroupName, Protocol, Port, VpcId, TargetType]' --output json",
    "Classic Load Balancers": "aws elb describe-load-balancers --query 'LoadBalancerDescriptions[*].[LoadBalancerName, DNSName, VPCId]' --output json",
    "CloudFront Distributions": "aws cloudfront list-distributions --query 'DistributionList.Items[*].[Id, DomainName, Enabled, Status]' --output json",
    
    # Storage
    "S3 Buckets": "aws s3api list-buckets --query 'Buckets[*].[Name, CreationDate]' --output json",
    "EFS File Systems": "aws efs describe-file-systems --query 'FileSystems[*].[FileSystemId, Name, LifeCycleState, PerformanceMode]' --output json",
    "EBS Volumes": "aws ec2 describe-volumes --query 'Volumes[*].[VolumeId, Size, State, VolumeType, AvailabilityZone, Attachments[0].InstanceId]' --output json",
    
    # VPC/Networking Resources
    "VPCs": "aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId, CidrBlock, IsDefault, Tags[?Key==`Name`].Value | [0]]' --output json",
    "Subnets": "aws ec2 describe-subnets --query 'Subnets[*].[SubnetId, VpcId, CidrBlock, AvailabilityZone, MapPublicIpOnLaunch, Tags[?Key==`Name`].Value | [0]]' --output json",
    "Route Tables": "aws ec2 describe-route-tables --query 'RouteTables[*].[RouteTableId, VpcId, Associations[0].SubnetId, Tags[?Key==`Name`].Value | [0]]' --output json",
    "Internet Gateways": "aws ec2 describe-internet-gateways --query 'InternetGateways[*].[InternetGatewayId, Attachments[0].VpcId, Tags[?Key==`Name`].Value | [0]]' --output json",
    "NAT Gateways": "aws ec2 describe-nat-gateways --query 'NatGateways[*].[NatGatewayId, VpcId, SubnetId, State, NatGatewayAddresses[0].PrivateIp, NatGatewayAddresses[0].PublicIp]' --output json",
    "Transit Gateways": "aws ec2 describe-transit-gateways --query 'TransitGateways[*].[TransitGatewayId, State, Description]' --output json",
    "VPC Endpoints": "aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[*].[VpcEndpointId, VpcId, ServiceName, VpcEndpointType, State]' --output json",
    #"Direct Connect": "aws directconnect describe-connections --query 'connections[*].[connectionId, connectionName, connectionState, bandwidth]' --output json",
    
    # Security Resources
    "Security Groups": "aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId, GroupName, VpcId, Description]' --output json",
    "Network ACLs": "aws ec2 describe-network-acls --query 'NetworkAcls[*].[NetworkAclId, VpcId, IsDefault, Tags[?Key==`Name`].Value | [0]]' --output json",
    "Secrets Manager Secrets": "aws secretsmanager list-secrets --query 'SecretList[*].[ARN, Name, Description]' --output json",
    "KMS Keys": "aws kms list-keys --query 'Keys[*].[KeyId]' --output json",
    "ACM Certificates": "aws acm list-certificates --query 'CertificateSummaryList[*].[CertificateArn, DomainName, Status]' --output json",
    "WAF Web ACLs": "aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[*].[Name, Id, ARN]' --output json",
    
    # DNS/Domain Services
    "Route 53 Hosted Zones": "aws route53 list-hosted-zones --query 'HostedZones[*].[Id, Name, Config.PrivateZone]' --output json",
    
    # Monitoring & Logging
    "CloudWatch Alarms": "aws cloudwatch describe-alarms --query 'MetricAlarms[*].[AlarmName, Namespace, MetricName, Statistic, Period, AlarmActions]' --output json",
    "CloudWatch Log Groups": "aws logs describe-log-groups --query 'logGroups[*].[logGroupName, retentionInDays, storedBytes]' --output json",
    
    # Identity Resources
    "IAM Roles": "aws iam list-roles --query 'Roles[*].[RoleName, Path, Arn]' --output json",
    "IAM Policies": "aws iam list-policies --scope Local --query 'Policies[*].[PolicyName, Arn]' --output json",
    
    # Application Integration
    "SNS Topics": "aws sns list-topics --query 'Topics[*].[TopicArn]' --output json",
    "SQS Queues": "aws sqs list-queues --query 'QueueUrls' --output json",
    "EventBridge Rules": "aws events list-rules --query 'Rules[*].[Name, EventPattern, ScheduleExpression, State]' --output json"
}

def run_aws_command(command, profile, region):
    """Runs an AWS CLI command and returns JSON output."""
    full_command = f"{command} --profile {profile} --region {region}"
    try:
        result = subprocess.run(full_command, shell=True, check=True, capture_output=True, text=True)
        return json.loads(result.stdout) if result.stdout.strip() else []
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {full_command}\n{e}")
        return []

def collect_aws_inventory(profile, region, resources=None):
    """Runs all AWS commands and gathers inventory data."""
    inventory_data = {}
    commands_to_run = AWS_COMMANDS
    
    # If specific resources are requested, filter the commands
    if resources:
        commands_to_run = {k: v for k, v in AWS_COMMANDS.items() if k in resources}
    
    # Track progress
    total_commands = len(commands_to_run)
    current_command = 0
    
    for resource, command in commands_to_run.items():
        current_command += 1
        print(f"[{current_command}/{total_commands}] Collecting {resource} data...")
        inventory_data[resource] = run_aws_command(command, profile, region)
    
    return inventory_data

def save_to_json(data, output_file):
    """Saves data to a JSON file."""
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Saved JSON report: {output_file}")

def save_to_csv(data, output_file):
    """Saves data to a CSV file (flattens JSON into tabular format)."""
    flat_data = []
    for category, records in data.items():
        if not records:
            continue
            
        for record in records:
            # Create a row with category and all values from the record
            row = {"Resource_Type": category}
            
            # Handle different shapes of data
            if isinstance(record, list):
                for i, value in enumerate(record):
                    row[f"Value_{i+1}"] = value
            elif isinstance(record, dict):
                for key, value in record.items():
                    row[key] = value
            else:
                row["Value"] = record
                
            flat_data.append(row)
    
    # Create CSV file
    if flat_data:
        # Get all unique field names
        fieldnames = set()
        for row in flat_data:
            fieldnames.update(row.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flat_data)
        
        print(f"Saved CSV report: {output_file}")
    else:
        print("No data to save to CSV file")

def save_to_html(data, output_file):
    """Saves data to an HTML report with tables for each resource type."""
    html_content = []
    
    # Add HTML header with some basic styling
    html_content.append("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Inventory Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #232f3e; }
            h2 { color: #232f3e; margin-top: 30px; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
            th { background-color: #232f3e; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .summary { display: flex; flex-wrap: wrap; margin: 20px 0; }
            .summary-item { 
                background-color: #eaeded; 
                border-radius: 5px; 
                padding: 15px; 
                margin: 5px; 
                min-width: 200px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.12);
            }
            .count { font-size: 24px; font-weight: bold; margin: 10px 0; }
            .resource-type { font-weight: bold; }
            
            /* Make tables responsive */
            @media screen and (max-width: 600px) {
                table { display: block; overflow-x: auto; }
            }
        </style>
    </head>
    <body>
        <h1>AWS Inventory Report</h1>
    """)
    
    # Add generated timestamp and metadata
    html_content.append(f"<p><strong>Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
    
    # Create summary section
    html_content.append("<h2>Resource Summary</h2>")
    html_content.append("<div class='summary'>")
    
    # Sort resources by count for better visualization
    resource_counts = []
    for resource_type, resources in data.items():
        count = len(resources) if isinstance(resources, list) else 1
        if count > 0:
            resource_counts.append((resource_type, count))
    
    # Sort by count in descending order
    resource_counts.sort(key=lambda x: x[1], reverse=True)
    
    for resource_type, count in resource_counts:
        html_content.append(f"""
        <div class='summary-item'>
            <div class='resource-type'>{resource_type}</div>
            <div class='count'>{count}</div>
        </div>
        """)
    
    html_content.append("</div>")
    
    # Add a table of contents for easier navigation
    html_content.append("<h2>Table of Contents</h2>")
    html_content.append("<ul>")
    for resource_type, resources in sorted(data.items()):
        if resources:
            # Create an anchor-friendly ID
            section_id = resource_type.lower().replace(' ', '-').replace('/', '-')
            html_content.append(f"<li><a href='#{section_id}'>{resource_type}</a> ({len(resources) if isinstance(resources, list) else 1})</li>")
    html_content.append("</ul>")
    
    # Create detailed sections for each resource type
    for resource_type, resources in sorted(data.items()):
        if not resources:
            continue
        
        # Create an anchor-friendly ID
        section_id = resource_type.lower().replace(' ', '-').replace('/', '-')
        html_content.append(f"<h2 id='{section_id}'>{resource_type}</h2>")
        
        # Convert to HTML table
        if isinstance(resources, list) and resources:
            if isinstance(resources[0], list):
                # Create table header
                html_content.append("<table>")
                html_content.append("<tr>")
                for i in range(len(resources[0])):
                    html_content.append(f"<th>Column {i+1}</th>")
                html_content.append("</tr>")
                
                # Create table rows
                for resource in resources:
                    html_content.append("<tr>")
                    for value in resource:
                        # Handle None values and format JSON objects
                        if value is None:
                            formatted_value = ""
                        elif isinstance(value, (dict, list)):
                            formatted_value = f"<pre>{json.dumps(value, indent=2)}</pre>"
                        else:
                            formatted_value = str(value)
                        html_content.append(f"<td>{formatted_value}</td>")
                    html_content.append("</tr>")
                html_content.append("</table>")
            elif isinstance(resources[0], dict):
                # Get all unique keys
                all_keys = set()
                for resource in resources:
                    all_keys.update(resource.keys())
                
                # Create table header
                html_content.append("<table>")
                html_content.append("<tr>")
                for key in sorted(all_keys):
                    html_content.append(f"<th>{key}</th>")
                html_content.append("</tr>")
                
                # Create table rows
                for resource in resources:
                    html_content.append("<tr>")
                    for key in sorted(all_keys):
                        value = resource.get(key, "")
                        # Format JSON objects for better readability
                        if isinstance(value, (dict, list)):
                            formatted_value = f"<pre>{json.dumps(value, indent=2)}</pre>"
                        else:
                            formatted_value = str(value)
                        html_content.append(f"<td>{formatted_value}</td>")
                    html_content.append("</tr>")
                html_content.append("</table>")
            else:
                # Simple list
                html_content.append("<table>")
                html_content.append("<tr><th>Value</th></tr>")
                for value in resources:
                    formatted_value = str(value)
                    html_content.append(f"<tr><td>{formatted_value}</td></tr>")
                html_content.append("</table>")
    
    # Add a back to top link after each section
    html_content.append("<p><a href='#'>Back to top</a></p>")
    
    # Close HTML document
    html_content.append("</body></html>")
    
    # Write to file
    with open(output_file, "w") as f:
        f.write("".join(html_content))
    
    print(f"Saved HTML report: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="AWS Inventory Collection Script")
    parser.add_argument("--profile", required=True, help="AWS Profile Name")
    parser.add_argument("--region", required=True, help="AWS Region")
    parser.add_argument("--output", choices=["json", "csv", "html"], required=True, help="Output format")
    parser.add_argument("--resources", nargs="+", help="Specific resources to collect (default: all)")
    
    args = parser.parse_args()
    
    # Create reports directory if it doesn't exist
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_file = os.path.join(reports_dir, f"aws_inventory_{args.profile}_{args.region}_{timestamp}.{args.output}")
    
    print(f"Starting AWS inventory collection for region {args.region} using profile {args.profile}")
    
    # Collect inventory data
    inventory_data = collect_aws_inventory(args.profile, args.region, args.resources)
    
    # Save the data in the requested format
    if args.output == "json":
        save_to_json(inventory_data, output_file)
    elif args.output == "csv":
        save_to_csv(inventory_data, output_file)
    elif args.output == "html":
        save_to_html(inventory_data, output_file)
    
    print(f"AWS inventory collection complete. Report saved to {output_file}")

if __name__ == "__main__":
    main()