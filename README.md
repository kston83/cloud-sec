# cloud-security
Cloud Security Stuff


A collection of Python scripts for AWS security and compliance monitoring. These tools help generate detailed reports about various AWS security configurations and resources.

## Scripts Overview

1. **Secrets Manager Inventory** (`secrets.py`)
   - Generates reports of AWS Secrets Manager secrets and their rotation status
   - Tracks rotation events using CloudTrail
   - Supports multiple AWS profiles and regions

2. **Port and Protocol Analysis** (`aws_ports.py`)
   - Analyzes and documents all network ports and protocols in use
   - Covers Security Groups, ALBs, ECS tasks, NACLs, NAT Gateways, and VPC Endpoints
   - Generates consolidated port usage reports

3. **IAM User Analysis** (`iam_key.py`)
   - Reports on IAM users and their access keys
   - Tracks key age and last usage
   - Monitors password last used dates

## Prerequisites

- Python 3.6+
- boto3
- AWS credentials configured
- Required Python packages:
```
boto3
pyyaml
datetime
argparse
```

## Installation

1. Clone this repository
2. Install required packages:
```bash
pip install -r requirements.txt
```
3. Configure AWS credentials using either:
   - AWS CLI (`aws configure`)
   - Environment variables
   - IAM role

## Usage

### Secrets Manager Inventory

```bash
# Using config file
python secrets_inventory.py

# Using command line arguments
python secrets_inventory.py --profile myprofile --region us-east-1
```

### Port and Protocol Analysis

```bash
python vpc_ports.py --region us-east-1 --profile myprofile --output vpc_report.md
```

### IAM User Analysis

```bash
python iam_analysis.py --profile myprofile
```

## Configuration

### Secrets Manager Config (config.yaml)

```yaml
profiles:
  profile1:
    - us-east-1
    - us-west-2
  profile2:
    - eu-west-1

projects:
  profile1: "Project A"
  profile2: "Project B"
```

## Output

All scripts generate Markdown reports containing detailed information about the analyzed resources:

- `{profile}_secrets_report.md`: Secrets Manager inventory and rotation status
- `vpc_ports_and_protocols.md`: Network configuration and port usage
- `{profile}_iam_users_report.md`: IAM users and access keys report

## Permissions Required

The scripts require the following AWS permissions:

### Secrets Manager Inventory
- secretsmanager:ListSecrets
- cloudtrail:LookupEvents

### Port and Protocol Analysis
- ec2:DescribeSecurityGroups
- ec2:DescribeNetworkAcls
- ec2:DescribeNatGateways
- ec2:DescribeVpcEndpoints
- elasticloadbalancing:DescribeLoadBalancers
- elasticloadbalancing:DescribeListeners
- ecs:ListClusters
- ecs:ListTasks
- ecs:DescribeTasks
- ecs:DescribeTaskDefinition

### IAM User Analysis
- iam:ListUsers
- iam:ListAccessKeys
- iam:GetAccessKeyLastUsed

## Best Practices

1. Always use the principle of least privilege when configuring AWS credentials
2. Regularly rotate access keys used by these scripts
3. Store sensitive configuration data securely
4. Review generated reports for security compliance
5. Set up automated running of these scripts for regular monitoring

## Error Handling

All scripts include error handling and will:
- Log errors to stdout
- Continue processing when possible
- Exit with status code 1 on critical errors

## Contributing

Feel free to submit issues and enhancement requests!

## License

[Insert your chosen license here]
