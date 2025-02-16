# cloud-security

A collection of Python scripts for AWS security and compliance monitoring. These tools generate detailed reports about various AWS configurations, resources, and best-practice checks.

## Table of Contents

- [cloud-security](#cloud-security)
  - [Table of Contents](#table-of-contents)
  - [Scripts Overview](#scripts-overview)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Secrets Manager Inventory (`secrets.py`)](#secrets-manager-inventory-secretspy)
    - [Port and Protocol Analysis (`ports.py`)](#port-and-protocol-analysis-portspy)
    - [IAM User Analysis (`iam_key.py`)](#iam-user-analysis-iam_keypy)
    - [EC2 Inventory (`ec2_list.py`)](#ec2-inventory-ec2_listpy)
    - [Security Hub Findings (`sec_hub.py`)](#security-hub-findings-sec_hubpy)
    - [Trusted Advisor Analysis (`trustedadvisor.py`)](#trusted-advisor-analysis-trustedadvisorpy)
  - [Configuration](#configuration)
  - [Output](#output)
  - [Permissions Required](#permissions-required)
  - [Best Practices](#best-practices)
  - [Error Handling](#error-handling)
  - [Contributing](#contributing)

## Scripts Overview

1. **Secrets Manager Inventory** (`secrets.py`)
   - Scans AWS Secrets Manager secrets, logs their rotation status, and retrieves rotation events via CloudTrail.
   - Can optionally organize results by project, profile, and region (configurable via `config.yaml`).
   - Generates Markdown reports highlighting secrets nearing or past their rotation thresholds.

2. **Port and Protocol Analysis** (`ports.py`)
   - Analyzes network configuration across Security Groups, NACLs, NAT Gateways, VPC Endpoints, ALBs, ECS tasks, RDS instances, and more.
   - Identifies open ports, underlying protocols, and organizes them into a consolidated view.
   - Generates a Markdown report, including security recommendations.

3. **IAM User Analysis** (`iam_key.py`)
   - Enumerates IAM users, their associated access keys, key ages, and last-used dates.
   - Generates a Markdown report listing user details and key usage.

4. **EC2 Inventory** (`ec2_list.py`)
   - Collects information about EC2 instances (Instance ID, public/private IPs, AMI ID), infers OS from the AMI's `Name` field.
   - Outputs a table to the console and optionally to a file (in a tabular format using `tabulate`).

5. **Security Hub Findings** (`sec_hub.py`)
   - Retrieves findings from AWS Security Hub (e.g., Tenable or other sources) with specific filters.
   - Saves the findings in both JSON and CSV formats, highlighting resource ARNs, IPs, severity, timestamps, etc.

6. **Trusted Advisor Analysis** (`trustedadvisor.py`)
   - Pulls results from AWS Trusted Advisor checks (requires Business or Enterprise support plan).
   - Computes potential cost impact, risk levels, and recommended actions for each check.
   - Generates reports in multiple formats (JSON, CSV, Markdown, and optionally Excel) for in-depth analysis.

## Prerequisites

- **Python 3.6+**  
- **AWS Credentials** (configured via `aws configure`, environment variables, or IAM roles)
- **`requirements.txt`** (example contents):
  ```bash
  boto3
  pyyaml
  argparse
  datetime
  tabulate
  pandas
  xlsxwriter
  jinja2
  retry
  ```
  Install them via:
  ```bash
  pip install -r requirements.txt
  ```

> **Note**: Some scripts may run with fewer dependencies, but installing all packages above ensures full functionality across the suite.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/yourusername/cloud-security.git
   ```
2. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure AWS credentials** (if not already configured):
   ```bash
   aws configure
   ```

## Usage

### Secrets Manager Inventory (`secrets.py`)

1. **Configuration**  
   - Optionally create a `config.yaml` file specifying profiles, projects, and regions:
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
2. **Run**  
   ```bash
   # Scan all profiles/regions specified in config.yaml
   python secrets.py

   # Or specify a particular project on the command line
   python secrets.py --project "Project A"
   ```
3. **Description**  
   - Retrieves secrets from AWS Secrets Manager, skipping any that match exclusion prefixes.
   - Queries CloudTrail for recent rotation events.
   - Generates Markdown reports by project, profile, and region, indicating secrets nearing or past rotation deadlines.
   - Output is stored in a `reports/` folder, broken down by project, profile, region, and timestamp.

### Port and Protocol Analysis (`ports.py`)

```bash
python ports.py \
  --region us-east-1 \
  --profile myprofile \
  --output vpc_ports_and_protocols.md
```

**Description**  
- Gathers open ports and protocols for Security Groups, NACLs, NAT Gateways, VPC Endpoints, ALBs, ECS tasks, RDS instances, WAF configurations, and more.  
- Produces a consolidated Markdown report with usage counts, top exposed ports, and high-risk services.  
- Offers options to exclude certain services or analyze only WAF-related resources.  

**Key Arguments**  
- `--region <region>` (Required): The AWS region.  
- `--profile <profile>` (Optional): The AWS profile to use.  
- `--output <file>` (Optional): Output filename (defaults to `vpc_ports_and_protocols.md`).  
- `--exclude-services <list>` (Optional): Space-separated list of services to skip (e.g. `alb ecs nacl rds waf`).  
- `--waf-only` (Optional): If set, only WAF resources are analyzed.

### IAM User Analysis (`iam_key.py`)

```bash
python iam_key.py --profile myprofile
```

**Description**  
- Lists IAM users, their access keys, key ages, last-used dates, and password status.  
- Generates a Markdown report that includes user details and access key information.

**Key Arguments**  
- `--profile <profile>` (Optional): Use a specific AWS profile (defaults to `default`).  

**Output**  
- `<profile>_iam_users_report.md` listing IAM users and their associated keys.

### EC2 Inventory (`ec2_list.py`)

```bash
python ec2_list.py \
  --profile myprofile \
  --region us-east-1 \
  --outfile ec2_report.txt
```

**Description**  
- Fetches EC2 instance details (instance ID, public IP, private IP, AMI ID) and attempts to map the AMI ID to an OS name (via AMI's `Name` field).  
- Displays results in a nicely formatted table (via `tabulate`) and optionally writes the table to `--outfile`.  

**Key Arguments**  
- `--profile <profile>` (Required): The AWS profile to use.  
- `--region <region>` (Required): The AWS region to query.  
- `--outfile <path>` (Optional): Name of the file to save the table output.

### Security Hub Findings (`sec_hub.py`)

```bash
python sec_hub.py --region us-east-1 --profile myprofile --max-results 500
```

**Description**  
- Retrieves AWS Security Hub findings (e.g., from Tenable or other integrated products) based on certain filters (e.g., active workflow status, record state).  
- Saves findings to JSON and CSV, capturing resource ARNs, IP addresses, severities, etc.

**Key Arguments**  
- `--region <region>` (Required): The AWS region.  
- `--profile <profile>` (Optional): The AWS profile to use.  
- `--max-results <int>` (Optional): Max number of results to fetch (default `1000`). Use `0` to fetch all.

### Trusted Advisor Analysis (`trustedadvisor.py`)

```bash
python trustedadvisor.py
```

**Description**  
- Analyzes AWS Trusted Advisor checks (requires **Business** or **Enterprise** support plan).  
- Calculates risk levels, possible monthly cost savings, and recommended actions for each flagged resource.  
- Generates reports in JSON, CSV, Markdown, and optionally Excel with pivot tables (if `pandas` and `xlsxwriter` are installed).

**Key Points**  
- By default, runs for all profiles and regions in `config.yaml`.  
- Saves the output to a timestamped folder under `reports/`.

## Configuration

Some scripts (e.g., `secrets.py` and `trustedadvisor.py`) allow you to specify multiple AWS profiles, projects, and regions in a `config.yaml` file, which might look like:

```yaml
profiles:
  myprofile:
    - us-east-1
    - us-west-2
  anotherprofile:
    - eu-west-1

projects:
  myprofile: "Project A"
  anotherprofile: "Project B"
```

Adjust this as needed for your use case. Each script documents how it uses `config.yaml`, if at all.

## Output

Depending on the script, various output files (Markdown, JSON, CSV, Excel) are generated:

- **Secrets Manager Inventory** (`secrets.py`):  
  - Markdown reports organized by project, profile, and region.  
  - Stored in `reports/<project>/<profile>/<timestamp>/<region>_report.md`.  

- **Port and Protocol Analysis** (`ports.py`):  
  - Default filename is `vpc_ports_and_protocols.md` (configurable via `--output`).  

- **IAM User Analysis** (`iam_key.py`):  
  - `<profile>_iam_users_report.md`.  

- **EC2 Inventory** (`ec2_list.py`):  
  - Table output in console or written to the path specified by `--outfile`.  

- **Security Hub Findings** (`sec_hub.py`):  
  - Two files: `securityhub_findings_<region>_<timestamp>.json` and `.csv`.  

- **Trusted Advisor Analysis** (`trustedadvisor.py`):  
  - `<profile>_<region>_ta_report.md`, plus `.csv`, `.json`, and optionally `.xlsx` (with pivot tables).

## Permissions Required

Each script requires certain AWS permissions. Below is a non-exhaustive list:

1. **Secrets Manager Inventory (`secrets.py`)**  
   - `secretsmanager:ListSecrets`  
   - `cloudtrail:LookupEvents`  

2. **Port and Protocol Analysis (`ports.py`)**  
   - `ec2:DescribeSecurityGroups`  
   - `ec2:DescribeNetworkAcls`  
   - `ec2:DescribeNatGateways`  
   - `ec2:DescribeVpcEndpoints`  
   - `elasticloadbalancing:DescribeLoadBalancers`  
   - `elasticloadbalancing:DescribeListeners`  
   - `ecs:ListClusters`  
   - `ecs:ListTasks`  
   - `ecs:DescribeTasks`  
   - `ecs:DescribeTaskDefinition`  
   - `rds:DescribeDBInstances`  
   - `waf:ListWebACLs`, `waf:GetWebACL`, `waf:ListResourcesForWebACL`  
   - `waf-regional:ListWebACLs`, `waf-regional:GetWebACL`, `waf-regional:ListResourcesForWebACL`  

3. **IAM User Analysis (`iam_key.py`)**  
   - `iam:ListUsers`  
   - `iam:ListAccessKeys`  
   - `iam:GetAccessKeyLastUsed`  

4. **EC2 Inventory (`ec2_list.py`)**  
   - `ec2:DescribeInstances`  
   - `ec2:DescribeImages` (for OS mapping, optional)  

5. **Security Hub Findings** (`sec_hub.py`)**  
   - `securityhub:GetFindings`  

6. **Trusted Advisor Analysis** (`trustedadvisor.py`)**  
   - `support:DescribeTrustedAdvisorChecks`  
   - `support:DescribeTrustedAdvisorCheckResult`  
   - `support:DescribeTrustedAdvisorCheckSummaries`  
   - AWS **Business** or **Enterprise** support plan  

Always apply the **principle of least privilege** when granting these permissions.

## Best Practices

1. **Regular Credential Rotation**: Rotate the access keys used by these scripts regularly.  
2. **Audit & Logging**: Enable AWS CloudTrail (and optionally AWS Config) for complete visibility.  
3. **Automated Schedules**: Use cron jobs, AWS Systems Manager Automation, or other schedulers to run these scripts periodically.  
4. **Secure Storage**: Avoid committing sensitive configuration data/credentials to version control.  
5. **Review Findings**: Promptly remediate high-risk or noncompliant findings from these reports.

## Error Handling

- Each script logs errors to stdout or stderr.  
- When possible, scripts continue processing other resources if a partial error occurs.  
- Scripts typically exit with code `1` on critical/fatal errors.

## Contributing

Contributions are welcome!

- **Open an Issue** for bugs, suggestions, or feature requests.  
- **Submit a Pull Request** with your changes, ensuring code quality and documentation updates.  
- **Fork** the repository and customize as needed.

Please follow standard [GitHub Flow](https://docs.github.com/en/get-started/quickstart/github-flow) and keep changes well documented.