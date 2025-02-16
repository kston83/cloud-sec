import boto3
import yaml
import csv
import os
import datetime
import logging
import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass
from retry import retry
import pandas as pd
from jinja2 import Environment, FileSystemLoader


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

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TrustedAdvisorCheck:
    """Data class to store check information"""
    id: str
    name: str
    category: str
    description: str
    status: str
    resources_processed: int
    resources_flagged: int
    resources_suppressed: int
    cost_impact: float = 0.0
    risk_level: str = "Unknown"
    recommendation: str = ""
    console_link: str = ""

class TrustedAdvisorAnalyzer:
    """Enhanced Trusted Advisor analysis and reporting"""
    
    def __init__(self, profile: str, region: str, project_name: str):
        self.profile = profile
        self.region = region
        self.project_name = project_name
        self.output_dir = Path("reports") / datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.previous_results = self._load_previous_results()
        
        # Initialize AWS session
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.support_client = self.session.client('support', region_name='us-east-1')
        
    def _load_previous_results(self) -> Dict:
        """Load results from previous run for trend analysis"""
        try:
            previous_dirs = sorted(Path("reports").glob("*"))
            if not previous_dirs:
                return {}
            
            latest_report = max(previous_dirs[:-1]) if len(previous_dirs) > 1 else None
            if not latest_report:
                return {}
                
            with open(latest_report / "results.json", 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load previous results: {e}")
            return {}

    @retry(tries=3, delay=2, backoff=2)
    def get_check_details(self, check_id: str) -> Dict:
        """Get detailed information about a specific check with retry logic"""
        try:
            response = self.support_client.describe_trusted_advisor_check_result(
                checkId=check_id,
                language='en'
            )
            return response['result']
        except Exception as e:
            logger.error(f"Error getting check details for {check_id}: {e}")
            raise

    def analyze_checks(self) -> List[TrustedAdvisorCheck]:
        """Analyze all Trusted Advisor checks with enhanced information"""
        checks = []
        
        response = self.support_client.describe_trusted_advisor_checks(language='en')
        
        for check in response['checks']:
            try:
                details = self.get_check_details(check['id'])
                
                # Get check summary
                summary_response = self.support_client.describe_trusted_advisor_check_summaries(
                    checkIds=[check['id']]
                )
                summary = summary_response['summaries'][0]
                
                # Calculate risk level based on category and status
                risk_level = self._calculate_risk_level(check['category'], summary['status'])
                
                # Create console link
                console_link = f"https://console.aws.amazon.com/trustedadvisor/home?region={self.region}#/category/{check['category']}/check/{check['id']}"
                
                # Create check object with enhanced information
                ta_check = TrustedAdvisorCheck(
                    id=check['id'],
                    name=check['name'],
                    category=check['category'],
                    description=check['description'],
                    status=summary['status'],
                    resources_processed=summary.get('resourcesSummary', {}).get('resourcesProcessed', 0),
                    resources_flagged=summary.get('resourcesSummary', {}).get('resourcesFlagged', 0),
                    resources_suppressed=summary.get('resourcesSummary', {}).get('resourcesSuppressed', 0),
                    cost_impact=self._calculate_cost_impact(details),
                    risk_level=risk_level,
                    recommendation=check.get('recommendationDescription', ''),
                    console_link=console_link
                )
                
                checks.append(ta_check)
                
            except Exception as e:
                logger.error(f"Error processing check {check['id']}: {e}")
                continue
                
        return checks

    def _calculate_risk_level(self, category: str, status: str) -> str:
        """Calculate risk level based on category and status"""
        if status == 'error':
            return 'High'
        elif status == 'warning':
            return 'Medium'
        elif category in ['cost_optimizing', 'security']:
            return 'Medium' if status != 'ok' else 'Low'
        return 'Low'

    def _calculate_cost_impact(self, check_details: Dict) -> float:
        """Calculate potential cost impact from check details"""
        try:
            # This is a simplified example - you would need to implement proper
            # cost calculation logic based on your specific needs
            if 'costOptimizing' in check_details.get('categorySpecificSummary', {}):
                return check_details['categorySpecificSummary']['costOptimizing'].get('estimatedMonthlySavings', 0)
            return 0.0
        except Exception:
            return 0.0

    def generate_reports(self, checks: List[TrustedAdvisorCheck]):
        """Generate comprehensive reports in multiple formats"""
        self._save_json_results(checks)
        self._generate_csv_report(checks)
        self._generate_markdown_report(checks)
        self._generate_html_report(checks)
        self._generate_excel_report(checks)

    def _save_json_results(self, checks: List[TrustedAdvisorCheck]):
        """Save raw results for future trend analysis"""
        results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'checks': [vars(check) for check in checks]
        }
        
        with open(self.output_dir / 'results.json', 'w') as f:
            json.dump(results, f, indent=2)

    def _generate_csv_report(self, checks: List[TrustedAdvisorCheck]):
        """Generate detailed CSV report"""
        csv_file = self.output_dir / f"{self.profile}_{self.region}_ta_report.csv"
        
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "Check ID", "Name", "Category", "Status", "Risk Level",
                "Resources Processed", "Resources Flagged", "Cost Impact ($)",
                "Recommendation", "Console Link"
            ])
            
            for check in checks:
                writer.writerow([
                    check.id, check.name, check.category, check.status,
                    check.risk_level, check.resources_processed,
                    check.resources_flagged, check.cost_impact,
                    check.recommendation, check.console_link
                ])

    def _generate_markdown_report(self, checks: List[TrustedAdvisorCheck]):
        """Generate enhanced markdown report with executive summary"""
        md_file = self.output_dir / f"{self.profile}_{self.region}_ta_report.md"
        
        with open(md_file, 'w') as file:
            # Executive Summary
            file.write("# AWS Trusted Advisor Executive Summary\n\n")
            file.write(f"**Profile**: {self.profile}  \n")
            file.write(f"**Region**: {self.region}  \n")
            file.write(f"**Project**: {self.project_name}  \n")
            file.write(f"**Report Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n\n")
            
            # Summary Statistics
            high_risk = sum(1 for check in checks if check.risk_level == 'High')
            medium_risk = sum(1 for check in checks if check.risk_level == 'Medium')
            total_cost_impact = sum(check.cost_impact for check in checks)
            
            file.write("## Key Findings\n\n")
            file.write(f"- **High Risk Issues**: {high_risk}\n")
            file.write(f"- **Medium Risk Issues**: {medium_risk}\n")
            file.write(f"- **Potential Cost Savings**: ${total_cost_impact:,.2f}/month\n\n")
            
            # Detailed Findings
            file.write("## Detailed Findings\n\n")
            for check in sorted(checks, key=lambda x: (x.risk_level == 'High', x.risk_level == 'Medium'), reverse=True):
                file.write(f"### {check.name}\n\n")
                file.write(f"- **Risk Level**: {check.risk_level}\n")
                file.write(f"- **Category**: {check.category}\n")
                file.write(f"- **Status**: {check.status}\n")
                file.write(f"- **Resources Affected**: {check.resources_flagged}/{check.resources_processed}\n")
                if check.cost_impact > 0:
                    file.write(f"- **Potential Monthly Savings**: ${check.cost_impact:,.2f}\n")
                file.write(f"- **Recommendation**: {check.recommendation}\n")
                file.write(f"- **Console Link**: {check.console_link}\n\n")

    def _generate_html_report(self, checks: List[TrustedAdvisorCheck]):
        """Generate interactive HTML report with charts"""
        # Implementation would include creating HTML with charts using a template engine
        # This is a placeholder for the implementation
        pass

    def _generate_excel_report(self, checks: List[TrustedAdvisorCheck]):
        """Generate Excel report with multiple sheets and pivot tables"""
        excel_file = self.output_dir / f"{self.profile}_{self.region}_ta_report.xlsx"
        
        # Convert checks to DataFrame
        df = pd.DataFrame([vars(check) for check in checks])
        
        with pd.ExcelWriter(excel_file, engine='xlsxwriter') as writer:
            # Summary sheet
            df.to_excel(writer, sheet_name='Raw Data', index=False)
            
            # Create pivot tables
            pivot = pd.pivot_table(
                df,
                values=['resources_flagged', 'cost_impact'],
                index=['category', 'risk_level'],
                aggfunc='sum'
            )
            pivot.to_excel(writer, sheet_name='Summary')

def main(env=None, region=None):
    """Main function with improved error handling and logging"""
    try:
        config = load_config()
        
        if env and region:
            project_name = config.get('projects', {}).get(env, "Unknown")
            analyzer = TrustedAdvisorAnalyzer(env, region, project_name)
            checks = analyzer.analyze_checks()
            analyzer.generate_reports(checks)
        else:
            for profile in config.get('profiles', []):
                project_name = config.get('projects', {}).get(profile, "Unknown")
                regions = config.get('regions', {}).get(profile, [])
                
                for region in regions:
                    analyzer = TrustedAdvisorAnalyzer(profile, region, project_name)
                    checks = analyzer.analyze_checks()
                    analyzer.generate_reports(checks)
                    
    except Exception as e:
        logger.error(f"Error in main execution: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        main(env=sys.argv[1], region=sys.argv[2])
    else:
        main()