import subprocess
import json
import csv
from pathlib import Path
import sys
import os

class LocalImageScanner:
    def __init__(self, image_name, output_dir=None):
        """
        Initialize scanner with image name and optional output directory
        
        Args:
            image_name (str): Name of the Docker image to scan
            output_dir (str, optional): Override default reports directory location
        """
        # Clean image name for use in directory name (replace / and : with _)
        safe_image_name = image_name.replace('/', '_').replace(':', '_')
        
        # Get current date in YYYYMMDD format
        from datetime import datetime
        date_str = datetime.now().strftime('%Y%m%d')
        
        # Get the directory where the script is located
        script_dir = Path(__file__).parent.absolute()
        
        # Create reports directory in script location if output_dir not specified
        if output_dir is None:
            base_reports_dir = script_dir / "reports"
            self.output_dir = base_reports_dir / f"{safe_image_name}_{date_str}"
        else:
            self.output_dir = Path(output_dir)
        
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.sbom_file = self.output_dir / "sbom.json"
        self.vuln_file = self.output_dir / "vulnerabilities.json"
        self.report_file = self.output_dir / "vulnerability_analysis.csv"

    def verify_image_exists(self, image_name):
        """Verify that the specified image exists locally"""
        # First try docker images
        docker_result = subprocess.run(
            ["docker", "image", "ls", image_name, "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True
        )
        
        # If docker doesn't find it, try grype directly to verify it can access the image
        if docker_result.returncode != 0 or not docker_result.stdout.strip():
            grype_test = subprocess.run(
                ["grype", image_name, "--help"],
                capture_output=True,
                text=True
            )
            if grype_test.returncode != 0:
                raise ValueError(
                    f"Image '{image_name}' could not be accessed.\n"
                    f"Docker error: {docker_result.stderr}\n"
                    f"Grype error: {grype_test.stderr}"
                )

    def generate_sbom(self, image_name):
        """Generate SBOM using Syft with detailed package information"""
        print(f"Generating SBOM for {image_name} with Syft...")
        subprocess.run([
            "syft",
            image_name,
            "-o", "json",
            "--file", str(self.sbom_file),
            "--scope", "all-layers"
        ], check=True)

    def scan_with_grype(self):
        """Scan using Grype with the Syft SBOM as input"""
        print("Scanning with Grype...")
        subprocess.run([
            "grype",
            f"sbom:{str(self.sbom_file)}",
            "--output", "json",
            "--file", str(self.vuln_file),
            "--add-cpes-if-none"
        ], check=True)

    def categorize_package(self, package_info):
        """Categorize package based on type and location"""
        pkg_type = package_info.get("type", "").lower()
        path = package_info.get("path", "").lower()
        
        if "node_modules" in path:
            return "Node.js Dependencies"
        elif pkg_type in ["npm", "nodejs"]:
            return "Node.js Application"
        elif "requirements.txt" in path or "setup.py" in path:
            return "Python Dependencies"
        elif pkg_type in ["gem"]:
            return "Ruby Dependencies"
        elif pkg_type in ["deb", "rpm"]:
            return "Base Image"
        elif pkg_type == "binary":
            return "Binary Components"
        elif "cargo.toml" in path:
            return "Rust Dependencies"
        elif "go.mod" in path:
            return "Go Dependencies"
        else:
            return "Other"

    def parse_reports(self):
        """Parse and correlate SBOM and vulnerability data"""
        print("Analyzing vulnerability sources...")
        
        # Load SBOM data
        with open(self.sbom_file) as f:
            sbom_data = json.load(f)
        
        # Create package lookup from SBOM
        package_info = {}
        for artifact in sbom_data.get("artifacts", []):
            artifact_id = artifact.get("id", "")
            metadata = artifact.get("metadata", {})
            
            # Extract layer information
            layer_id = "Unknown"
            path = ""
            
            locations = artifact.get("locations", [])
            if locations:
                for location in locations:
                    if location.get("layerID"):
                        layer_id = location.get("layerID")
                        path = location.get("path", "")
                        break
                    elif location.get("layer", {}).get("digest"):
                        layer_id = location["layer"]["digest"]
                        path = location.get("path", "")
                        break
            
            found_by = (
                artifact.get("foundBy") or 
                artifact.get("type") or 
                metadata.get("foundBy") or 
                "Unknown"
            )
            
            package_info[artifact_id] = {
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "type": artifact.get("type"),
                "path": path,
                "layer": layer_id,
                "foundBy": found_by
            }
        
        # Load and process vulnerabilities
        with open(self.vuln_file) as f:
            vuln_data = json.load(f)
        
        report = []
        for match in vuln_data.get("matches", []):
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            pkg_id = artifact.get("id", "")
            pkg_data = package_info.get(pkg_id, {})
            
            # Get CVSS score
            cvss_score = "Unknown"
            cvss_data = vulnerability.get("cvss", [])
            if cvss_data:
                primary_scores = [cvss for cvss in cvss_data if cvss.get("type") == "Primary"]
                if primary_scores and "metrics" in primary_scores[0]:
                    cvss_score = primary_scores[0]["metrics"].get("baseScore", "Unknown")
                elif cvss_data and "metrics" in cvss_data[0]:
                    cvss_score = cvss_data[0]["metrics"].get("baseScore", "Unknown")
            
            entry = {
                "CVE": vulnerability.get("id", ""),
                "Package": artifact.get("name", ""),
                "Version": artifact.get("version", ""),
                "Type": artifact.get("type", ""),
                "Path": pkg_data.get("path", ""),
                "Layer": pkg_data.get("layer", "Unknown"),
                "Category": self.categorize_package(pkg_data),
                "Severity": vulnerability.get("severity", ""),
                "Description": vulnerability.get("description", ""),
                "FoundBy": pkg_data.get("foundBy", "Unknown"),
                "Fix_Version": (vulnerability.get("fix", {}).get("versions", []) or ["Unknown"])[0],
                "CVSS": cvss_score
            }
            
            report.append(entry)
        
        return report

    def save_report(self, report):
        """Save the analysis report with category grouping"""
        print(f"Saving detailed report to {self.report_file}...")
        
        fieldnames = [
            "Category",
            "CVE",
            "Package",
            "Version",
            "Type",
            "Path",
            "Layer",
            "Severity",
            "Description",
            "FoundBy",
            "Fix_Version",
            "CVSS"
        ]
        
        # Sort by category and severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_report = sorted(
            report,
            key=lambda x: (
                x["Category"],
                severity_order.get(x["Severity"], 4)
            )
        )
        
        with open(self.report_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            current_category = None
            for entry in sorted_report:
                if entry["Category"] != current_category:
                    if current_category is not None:
                        writer.writerow({field: "" for field in fieldnames})
                    current_category = entry["Category"]
                writer.writerow(entry)

    def generate_summary(self, report):
        """Generate a summary of findings by category"""
        summary = {}
        for entry in report:
            category = entry["Category"]
            severity = entry["Severity"]
            
            if category not in summary:
                summary[category] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            
            if severity in summary[category]:
                summary[category][severity] += 1
        
        print("\nVulnerability Summary:")
        print("-" * 80)
        for category, counts in sorted(summary.items()):
            print(f"\n{category}:")
            print(f"  Critical: {counts['Critical']}")
            print(f"  High: {counts['High']}")
            print(f"  Medium: {counts['Medium']}")
            print(f"  Low: {counts['Low']}")
        print("-" * 80)

    def scan_image(self, image_name):
        """Main method to scan a local image"""
        try:
            # Verify tools are available
            for tool in ["syft", "grype"]:
                if subprocess.run(["which", tool], capture_output=True).returncode != 0:
                    raise RuntimeError(
                        f"{tool} is not installed. Please install it first.\n"
                        f"Visit: https://github.com/anchore/{tool} for installation instructions."
                    )

            # Verify image exists locally
            self.verify_image_exists(image_name)

            # Generate SBOM and scan
            self.generate_sbom(image_name)
            self.scan_with_grype()

            # Analyze and generate report
            report = self.parse_reports()
            self.save_report(report)
            self.generate_summary(report)

            print(f"\nScan results directory: {self.output_dir}")
            print(f"Detailed report: {self.report_file}")
            
            return report

        except Exception as e:
            print(f"Error scanning image: {str(e)}")
            raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Local Docker Image Vulnerability Scanner")
    parser.add_argument(
        "image",
        help="Name of the local Docker image to scan (e.g., 'myapp:latest')"
    )
    parser.add_argument(
        "--output-dir",
        help="Override default reports directory location"
    )
    
    args = parser.parse_args()
    
    scanner = LocalImageScanner(args.image, output_dir=args.output_dir)
    scanner.scan_image(args.image)

if __name__ == "__main__":
    main()