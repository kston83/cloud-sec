import subprocess
import json
import csv
from pathlib import Path
import sys

# Configuration
IMAGE_NAME = "artifactory.com/docker-local/app" # Update with your image location, this is fake
DEFAULT_TAG = "latest" # Update with the tag to scan
SYFT_SBOM = "sbom.json"
GRYPE_OUTPUT = "vulnerabilities.json"
FINAL_REPORT = "vulnerability_analysis.csv"

def pull_image(image_name):
    print(f"Pulling image: {image_name}")
    subprocess.run(["docker", "pull", image_name], check=True)

def generate_sbom(image_name, output_file):
    """Generate SBOM using Syft with detailed package information"""
    print("Generating SBOM with Syft...")
    subprocess.run([
        "syft",
        image_name,
        "-o", "json",
        "--file", output_file,
        "--scope", "all-layers"
    ], check=True)

def scan_with_grype(image_name, sbom_file, output_file):
    """Scan using Grype with the Syft SBOM as input"""
    print("Scanning with Grype...")
    subprocess.run([
        "grype",
        f"sbom:{sbom_file}",
        "--output", "json",
        "--file", output_file,
        "--add-cpes-if-none"
    ], check=True)

def categorize_package(package_info):
    """Categorize package based on type and location"""
    pkg_type = package_info.get("type", "").lower()
    path = package_info.get("path", "").lower()
    
    if "node_modules" in path:
        return "Node.js Dependencies"
    elif pkg_type in ["npm", "nodejs"]:
        return "Node.js Application"
    elif "jfrog" in path.lower():
        return "JFrog Components"
    elif pkg_type in ["deb", "rpm"]:
        return "Base Image"
    elif pkg_type == "binary":
        return "Binary Components"
    else:
        return "Other"

def parse_reports(sbom_file, vuln_file):
    """Parse and correlate SBOM and vulnerability data"""
    print("Analyzing vulnerability sources...")
    
    # Load SBOM data
    try:
        with open(sbom_file) as f:
            sbom_data = json.load(f)
        artifact_count = len(sbom_data.get('artifacts', []))
        print(f"Loaded SBOM data with {artifact_count} artifacts")
        
        # Debug: Print structure of first artifact
        if sbom_data.get('artifacts'):
            print("\nSample SBOM artifact structure:")
            print(json.dumps(sbom_data['artifacts'][0], indent=2))
    except Exception as e:
        print(f"Error loading SBOM data: {str(e)}")
        return []
    
    # Load vulnerability data
    try:
        with open(vuln_file) as f:
            vuln_data = json.load(f)
        match_count = len(vuln_data.get('matches', []))
        print(f"\nLoaded vulnerability data with {match_count} matches")
        
        # Debug: Print structure of first vulnerability match
        if vuln_data.get('matches'):
            print("\nSample vulnerability match structure:")
            print(json.dumps(vuln_data['matches'][0], indent=2))
    except Exception as e:
        print(f"Error loading vulnerability data: {str(e)}")
        return []

    # Create package lookup from SBOM
    package_info = {}
    for artifact in sbom_data.get("artifacts", []):
        artifact_id = artifact.get("id", "")
        metadata = artifact.get("metadata", {})
        
        # Debug: Print full metadata for first few artifacts
        if len(package_info) < 2:
            print(f"\nFull metadata for artifact {artifact_id}:")
            print(json.dumps(metadata, indent=2))
        
        # Extract layer information from various possible locations
        layer_id = "Unknown"
        path = ""
        
        # Try to get location information
        locations = artifact.get("locations", [])
        if locations:
            # Try different possible layer ID fields
            for location in locations:
                if location.get("layerID"):
                    layer_id = location.get("layerID")
                    path = location.get("path", "")
                    break
                elif location.get("layer", {}).get("digest"):
                    layer_id = location["layer"]["digest"]
                    path = location.get("path", "")
                    break
        
        # Get foundBy from multiple possible locations
        found_by = (
            artifact.get("foundBy") or 
            artifact.get("type") or 
            metadata.get("foundBy") or 
            "Unknown"
        )
        
        # Store normalized package info
        package_info[artifact_id] = {
            "name": artifact.get("name"),
            "version": artifact.get("version"),
            "type": artifact.get("type"),
            "path": path,
            "layer": layer_id,
            "foundBy": found_by
        }
    
    # Process vulnerabilities
    report = []
    for match in vuln_data.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        pkg_id = artifact.get("id", "")
        pkg_data = package_info.get(pkg_id, {})
        
        # Get CVSS score from the vulnerability data
        cvss_score = "Unknown"
        cvss_data = vulnerability.get("cvss", [])
        if cvss_data:
            # Try to get primary score first
            primary_scores = [cvss for cvss in cvss_data if cvss.get("type") == "Primary"]
            if primary_scores and "metrics" in primary_scores[0]:
                cvss_score = primary_scores[0]["metrics"].get("baseScore", "Unknown")
            # Fall back to any score if no primary score
            elif cvss_data and "metrics" in cvss_data[0]:
                cvss_score = cvss_data[0]["metrics"].get("baseScore", "Unknown")
        
        entry = {
            "CVE": vulnerability.get("id", ""),
            "Package": artifact.get("name", ""),
            "Version": artifact.get("version", ""),
            "Type": artifact.get("type", ""),
            "Path": pkg_data.get("path", ""),
            "Layer": pkg_data.get("layer", "Unknown"),
            "Category": categorize_package(pkg_data),
            "Severity": vulnerability.get("severity", ""),
            "Description": vulnerability.get("description", ""),
            "FoundBy": pkg_data.get("foundBy", "Unknown"),
            "Fix_Version": (vulnerability.get("fix", {}).get("versions", []) or ["Unknown"])[0],
            "CVSS": cvss_score
        }
        
        # Debug: Print first few entries
        if len(report) < 2:
            print(f"\nSample report entry:")
            print(json.dumps(entry, indent=2))
            
        report.append(entry)
    
    return report

def save_report(report, output_file):
    """Save the analysis report with category grouping"""
    print(f"Saving detailed report to {output_file}...")
    
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
    sorted_report = sorted(
        report,
        key=lambda x: (x["Category"], 
                      {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["Severity"], 4))
    )
    
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        current_category = None
        for entry in sorted_report:
            if entry["Category"] != current_category:
                # Add a blank row between categories
                if current_category is not None:
                    writer.writerow({field: "" for field in fieldnames})
                current_category = entry["Category"]
            writer.writerow(entry)

def generate_summary(report):
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
    for category, counts in summary.items():
        print(f"\n{category}:")
        print(f"  Critical: {counts['Critical']}")
        print(f"  High: {counts['High']}")
        print(f"  Medium: {counts['Medium']}")
        print(f"  Low: {counts['Low']}")
    print("-" * 80)

def main(image_name=None):
    try:
        if not image_name:
            image_name = f"{IMAGE_NAME}:{DEFAULT_TAG}"

        # Ensure tools are available
        for tool in ["syft", "grype"]:
            if not subprocess.run(["which", tool], capture_output=True).returncode == 0:
                print(f"Error: {tool} is not installed. Please install it first.")
                print(f"Visit: https://github.com/anchore/{tool} for installation instructions.")
                sys.exit(1)

        # Pull image
        pull_image(image_name)

        # Generate SBOM and scan
        generate_sbom(image_name, SYFT_SBOM)
        scan_with_grype(image_name, SYFT_SBOM, GRYPE_OUTPUT)

        # Analyze and generate report
        report = parse_reports(SYFT_SBOM, GRYPE_OUTPUT)
        save_report(report, FINAL_REPORT)
        generate_summary(report)

        print(f"\nDetailed report saved to: {FINAL_REPORT}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Layer-aware Vulnerability Analyzer")
    parser.add_argument(
        "--image", 
        help="Docker image name with optional tag or digest (e.g., 'image:tag' or 'image@sha256:digest')"
    )
    args = parser.parse_args()
    main(image_name=args.image)