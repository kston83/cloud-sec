# cloud-security

A collection of Python scripts for AWS security and compliance monitoring, container security scanning, and code security analysis. These tools generate detailed reports about various AWS configurations, resources, best-practice checks, container vulnerabilities, and security-sensitive code patterns.

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
    - [Container Vulnerability Analysis (`artifactory_grype.py`)](#container-vulnerability-analysis-artifactory_grypepy)
    - [Local Container Scanner (`local_grype.py`)](#local-container-scanner-local_grypepy)
    - [React Security Scanner (`dangerhtml.py`)](#react-security-scanner-dangerhtmlpy)
    - [Secret Detection Scanner (`truff.py`)](#secret-detection-scanner-truffpy)
    - [Software EOL Checker (`syft_eol.py`)](#software-eol-checker-syft_eolpy)
    - [AWS Inventory Collection (`aws_inventory.py`)](#aws-inventory-collection-aws_inventorypy)
  - [Configuration](#configuration)
  - [Output](#output)
  - [Permissions Required](#permissions-required)
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

7. **Container Vulnerability Analysis** (`artifactory_grype.py`)
   - Scans container images from Artifactory for vulnerabilities using Syft and Grype.
   - Generates detailed Software Bill of Materials (SBOM) and vulnerability reports.
   - Provides layer-aware vulnerability analysis with categorization by component type.
   - Creates comprehensive CSV reports with severity ratings and CVSS scores.

8. **Local Container Scanner** (`local_grype.py`)
   - Scans local Docker images for vulnerabilities using Syft and Grype
   - Generates detailed SBOM and vulnerability analysis for locally available container images
   - Provides layer-aware vulnerability analysis with categorization by component type
   - Creates comprehensive CSV reports with severity ratings and CVSS scores

9. **React Security Scanner** (`dangerhtml.py`)
   - Scans React codebases for potentially unsafe usage of dangerouslySetInnerHTML.
   - Performs intelligent detection of sanitization methods and potentially unsafe variables.
   - Supports parallel processing for large codebases.
   - Generates detailed reports in multiple formats (Markdown, Obsidian, JSON, CSV).

10. **Secret Detection Scanner** (`truff.py`)
    - Automates TruffleHog scans across multiple Git repositories.
    - Supports both single repository and multi-repository directory structures.
    - Automatically updates repositories to latest versions before scanning.
    - Generates HTML reports organized by date and project.

11. **Software EOL Checker** (`syft_eol.py`)
    - Scans packages in container images or directories using Syft to identify end-of-life software.
    - Checks packages against the endoflife.date API to determine EOL status and days remaining.
    - Categorizes findings by severity (End of Life, Critical, Warning, Attention, OK).
    - Generates detailed reports in HTML or CSV format highlighting vulnerable components.

12. **AWS Inventory Collection** (`aws_inventory.py`)
    - Comprehensive inventory collection of AWS resources across various services.
    - Collects data on over 30 different resource types including EC2, RDS, Lambda, S3, VPC resources, and more.
    - Generates reports in multiple formats (JSON, CSV, HTML) with detailed information on each resource.
    - Includes summary statistics and resource counts in the HTML report format.

## Prerequisites

- **Python 3.6+**  
- **AWS Credentials** (configured via `aws configure`, environment variables, or IAM roles)
- **Syft and Grype** (required for container scanning)
- **Docker** (required for container scanning)
- **TruffleHog3** (required for secret scanning)
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
4. **Install required tools** (as needed):
   - Visit https://github.com/anchore/syft for Syft installation
   - Visit https://github.com/anchore/grype for Grype installation
   - Install TruffleHog3:
     ```bash
     pip install trufflehog3
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

### Container Vulnerability Analysis (`artifactory_grype.py`)

```bash
python artifactory_grype.py --image artifactory.com/docker-local/app:latest
```

**Description**  
- Pulls container images from Artifactory and performs comprehensive vulnerability scanning
- Generates detailed SBOM using Syft and vulnerability analysis using Grype
- Categorizes findings by component type (Node.js Dependencies, Base Image, etc.)
- Produces detailed CSV reports with severity levels, CVSS scores, and fix versions

**Key Arguments**  
- `--image <image>` (Optional): Docker image name with optional tag or digest (defaults to configuration in script)

**Output Files**  
- `sbom.json`: Software Bill of Materials in JSON format
- `vulnerabilities.json`: Raw vulnerability scan results
- `vulnerability_analysis.csv`: Detailed analysis report with:
  - Vulnerability categorization by component type
  - Severity levels and CVSS scores
  - Package information and layer details
  - Available fix versions
  - Organized by category and severity

### Local Container Scanner (`local_grype.py`)

```bash
python local_grype.py myapp:latest --output-dir /path/to/reports
```

**Description**  
- Scans local Docker images for vulnerabilities using Syft and Grype
- Generates detailed Software Bill of Materials (SBOM) using Syft
- Performs comprehensive vulnerability scanning with Grype
- Categorizes vulnerabilities by component type (Node.js, Python, Base Image, etc.)
- Creates detailed reports with severity levels, CVSS scores, and fix versions

**Key Arguments**  
- `image` (Required): Name of the local Docker image to scan (e.g., 'myapp:latest')
- `--output-dir` (Optional): Override default reports directory location

**Output Files**  
- `sbom.json`: Detailed Software Bill of Materials
- `vulnerabilities.json`: Raw vulnerability scan results
- `vulnerability_analysis.csv`: Comprehensive analysis report including:
  - Vulnerability categorization by component type
  - Severity levels and CVSS scores
  - Package information and layer details
  - Available fix versions
  - Findings organized by category and severity

### React Security Scanner (`dangerhtml.py`)

```bash
python dangerhtml.py /path/to/repository --output-format markdown --show-sanitized
```

**Description**  
- Scans React codebases for instances of dangerouslySetInnerHTML usage
- Detects proper sanitization implementations and potentially unsafe variables
- Supports Git repository analysis with automatic branch updates
- Processes files in parallel for improved performance on large codebases

**Key Arguments**  
- `repo_path` (Required): Path to the repository to scan
- `--branch`: Specific Git branch to scan (default: current branch)
- `--output`: Output directory for reports (default: "reports")
- `--max-size`: Maximum file size in MB to scan (default: 1)
- `--show-sanitized`: Include sanitized findings in the report
- `--no-update`: Skip updating the repository from remote
- `--verbose`: Enable detailed logging
- `--output-format`: Choose report format (markdown/obsidian/json/csv)

### Secret Detection Scanner (`truff.py`)

```bash
python truff.py --directory ~/repos --branch main
```

**Description**  
- Automates TruffleHog secret detection scans across Git repositories
- Can scan either a single repository or multiple repositories in a directory structure
- Updates repositories to latest versions before scanning
- Generates comprehensive HTML reports for each repository

**Key Arguments**  
- `--directory`, `-d`: Top-level directory containing Git repositories (default: ~/cms-repos)
- `--branch`, `-b`: Specific branch to scan (default: current branch)

**Output Structure**  
Reports are organized by date and project in the following structure:
```
~/auto_scans/
  └── YYYY-MM-DD/
      └── project_name/
          └── trufflehog_repo-name_YYYY-MM-DD.html
```

### Software EOL Checker (`syft_eol.py`)

```bash
python syft_eol.py alpine:latest --format html --alert-days 30 90 180
```

**Description**  
- Uses Syft to generate a Software Bill of Materials (SBOM) for container images or directories
- Checks each package against the endoflife.date API to determine EOL status
- Categorizes findings by severity: End of Life, Critical, Warning, Attention, OK
- Generates comprehensive reports highlighting packages at or near end-of-life

**Key Arguments**  
- `target` (Required): The container image or directory to analyze
- `--file`: Path to existing Syft output file instead of scanning a new target
- `--format`: Output format (html or csv, default: html)
- `--alert-days`: Three thresholds (in days) for Critical, Warning, and Attention alerts (default: 90 180 365)
- `--verbose`: Enable detailed output during scanning
- `--output`: Filename for the output report

**Output**  
- HTML or CSV report with:
  - Summary of EOL status across all packages
  - Detailed tables of packages with their EOL dates and status
  - Color-coded status indicators (End of Life, Critical, Warning, Attention, OK)
  - List of packages not supported by endoflife.date API

### AWS Inventory Collection (`aws_inventory.py`)

```bash
python aws_inventory.py --profile myprofile --region us-east-1 --output html
```

**Description**  
- Collects comprehensive inventory of AWS resources across 30+ services
- Gathers detailed information about compute, database, networking, security, and storage resources
- Generates formatted reports with resource details and counts
- Supports filtering to specific resource types if needed

**Key Arguments**  
- `--profile` (Required): AWS Profile Name to use for API calls
- `--region` (Required): AWS Region to inventory
- `--output` (Required): Output format (json, csv, or html)
- `--resources` (Optional): List of specific resource types to collect (default: all available)

**Output**  
- Report file in the specified format saved to the `reports/` directory
- HTML reports include:
  - Interactive resource summary with counts
  - Table of contents for easy navigation
  - Detailed tables for each resource type
  - Sortable and formatted data
- CSV and JSON formats for data analysis and import into other tools

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

- **Container Vulnerability Analysis** (`artifactory_grype.py`):
  - `sbom.json`: Detailed Software Bill of Materials
  - `vulnerabilities.json`: Raw vulnerability scan results
  - `vulnerability_analysis.csv`: Comprehensive analysis report

- **Software EOL Checker** (`syft_eol.py`):
  - `eol_report.html` or `eol_report.csv`: Detailed report of packages and their EOL status
  - `eol_report_unsupported.csv`: List of packages not supported by endoflife.date API (CSV output only)

- **AWS Inventory Collection** (`aws_inventory.py`):
  - `aws_inventory_<profile>_<region>_<timestamp>.<format>`: Complete inventory in JSON, CSV, or HTML format

- **React Security Scanner** (`dangerhtml.py`):
  - `<repo>_audit_<date>.md`: Markdown report with findings
  - `<repo>_audit_<date>.json`: JSON format (if specified)
  - `<repo>_audit_<date>.csv`: CSV format (if specified)

- **Secret Detection Scanner** (`truff.py`):
  - `trufflehog_<repo-name>_<date>.html`: HTML report with detected secrets

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

5. **Security Hub Findings (`sec_hub.py`)**  
   - `securityhub:GetFindings`  

6. **Trusted Advisor Analysis (`trustedadvisor.py`)**  
   - `support:DescribeTrustedAdvisorChecks`  
   - `support:DescribeTrustedAdvisorCheckResult`  
   - `support:DescribeTrustedAdvisorCheckSummaries`  
   - AWS **Business** or **Enterprise** support plan  

7. **Container Vulnerability Analysis** (`artifactory_grype.py`)
   - Docker daemon access
   - Read access to Artifactory repository
   - Local system permissions to run Syft and Grype

8. **Software EOL Checker** (`syft_eol.py`)
   - Docker daemon access (if scanning container images)
   - Local system permissions to run Syft
   - Internet access to query endoflife.date API

9. **AWS Inventory Collection** (`aws_inventory.py`)
   - Read-only permissions for all resources being inventoried
   - Extensive IAM read permissions including:
     - `ec2:Describe*`
     - `rds:Describe*`
     - `elasticache:Describe*`
     - `lambda:List*`
     - `s3api:List*`
     - And similar List/Describe permissions for all AWS services being inventoried

10. **Local Container Scanner** (`local_grype.py`)
   - Docker daemon access
   - Local system permissions to run Syft and Grype
   - Read access to local Docker images
   - Write permissions for output directory

11. **React Security Scanner** (`dangerhtml.py`)
   - Read access to target repository
   - Git access (if scanning Git repositories)
   - File system permissions for the target directory

12. **Secret Detection Scanner** (`truff.py`)
    - Read access to target repositories
    - Git access for repository updates
    - TruffleHog3 installation
    - Write permissions for output directory

Always apply the **principle of least privilege** when granting these permissions.

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