import json
import requests
import pandas as pd
from datetime import datetime, timedelta
import argparse
import subprocess
import os
import sys
from tabulate import tabulate
import re

def generate_syft_sbom(target, output_file="sbom.json", format="json"):
    """Generate an SBOM using Syft."""
    try:
        cmd = ["syft", target, "-o", format + "=" + output_file]
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"SBOM generated successfully: {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error generating SBOM: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: syft command not found. Please ensure Syft is installed.")
        print("Installation instructions: https://github.com/anchore/syft#installation")
        sys.exit(1)

def normalize_package_name(name):
    """Normalize package names for compatibility with endoflife.date API."""
    # List of known mappings based on the official API spec and common variations
    mappings = {
        # Programming languages
        "python": "python",
        "python3": "python",
        "pypy": "python",
        "cpython": "python",
        
        # JavaScript/Node
        "nodejs": "nodejs",
        "node.js": "nodejs",
        "node-js": "nodejs",
        "node": "nodejs",
        
        # PHP
        "php": "php",
        "php-fpm": "php",
        
        # Ruby
        "ruby": "ruby",
        "ruby-lang": "ruby",
        
        # Go
        "golang": "go",
        "go": "go",
        "go-lang": "go",
        
        # .NET
        "dotnet": "dotnet",
        ".net": "dotnet",
        "dotnetcore": "dotnetcore",
        ".net core": "dotnetcore",
        "dotnet core": "dotnetcore",
        "dotnet-core": "dotnetcore",
        "dotnetfx": "dotnetfx",
        ".net framework": "dotnetfx",
        "dotnet framework": "dotnetfx",
        "dotnet-framework": "dotnetfx",
        
        # Linux distributions
        "ubuntu": "ubuntu",
        "debian": "debian",
        "centos": "centos",
        "fedora": "fedora",
        "alpine": "alpine",
        "amazon-linux": "amazon-linux",
        "amazon linux": "amazon-linux",
        "amazonlinux": "amazon-linux",
        "amazonlinux2": "amazon-linux",
        "rhel": "rhel",
        "red hat enterprise linux": "rhel",
        "redhat": "rhel",
        "red-hat": "rhel",
        "opensuse": "opensuse",
        "suse": "opensuse",
        "freebsd": "freebsd",
        "sles": "sles",
        
        # Databases
        "postgresql": "postgresql",
        "postgres": "postgresql",
        "mysql": "mysql",
        "mysql-server": "mysql",
        "mysql-client": "mysql",
        "mariadb": "mariadb",
        "mariadb-server": "mariadb",
        "mariadb-client": "mariadb",
        "mongodb": "mongodb",
        "mongo": "mongodb",
        "redis": "redis",
        "elasticsearch": "elasticsearch",
        "mssqlserver": "mssqlserver",
        "mssql": "mssqlserver",
        "sql-server": "mssqlserver",
        "sqlserver": "mssqlserver",
        
        # Web servers and related
        "nginx": "nginx",
        "apache": "apache",
        "apache2": "apache",
        "httpd": "apache",
        "tomcat": "tomcat",
        "apache-tomcat": "tomcat",
        
        # Container and orchestration
        "docker": "docker",
        "kubernetes": "kubernetes",
        "k8s": "kubernetes",
        
        # CMS and frameworks
        "wordpress": "wordpress",
        "wp": "wordpress",
        "drupal": "drupal",
        "django": "django",
        "flask": "flask",
        "laravel": "laravel",
        "rails": "rails",
        "ruby-on-rails": "rails",
        "spring": "spring-framework",
        "spring-framework": "spring-framework",
        "spring-boot": "spring-boot",
        "springboot": "spring-boot",
        "symfony": "symfony",
        "wagtail": "wagtail",
        
        # JavaScript frameworks
        "jquery": "jquery",
        "react": "react",
        "angular": "angular",
        "vue": "vue",
        "vuejs": "vue",
        "vue.js": "vue",
        "nextjs": "nextjs",
        "next.js": "nextjs",
        "bootstrap": "bootstrap",
        
        # Message brokers
        "rabbitmq": "rabbitmq",
        
        # Other software
        "openssh": "openssh",
        "openssl": "openssl",
        "powershell": "powershell",
        "pwsh": "powershell",
        "qt": "qt",
        "ros": "ros",
        "robot-operating-system": "ros",
        "filemaker": "filemaker",
        "magento": "magento",
        
        # Operating Systems beyond Linux
        "windows": "windows",
        "win": "windows",
        "windows-server": "windowsserver",
        "windowsserver": "windowsserver",
        "windows-embedded": "windowsembedded",
        "windowsembedded": "windowsembedded",
        "macos": "macos",
        "mac-os": "macos",
        "mac": "macos",
        "osx": "macos",
        
        # Microsoft Office
        "office": "office",
        "ms-office": "office",
        "msoffice": "office",
        "microsoft-office": "office",
        
        # Other
        "elixir": "elixir",
        "perl": "perl",
        "godot": "godot",
        
        # Hardware/devices
        "iphone": "iphone",
        "ios": "iphone",
        "kindle": "kindle",
        "pixel": "pixel",
        "surface": "surface"
    }
    
    # Convert to lowercase and remove special characters
    normalized = name.lower()
    normalized = re.sub(r'[^a-z0-9]', '', normalized)
    
    # Check if we have a direct mapping
    for key, value in mappings.items():
        if normalized == re.sub(r'[^a-z0-9]', '', key.lower()):
            return value
            
    # For packages not in our mapping, return the original name
    return name

def normalize_version(version):
    """Normalize version string for compatibility with endoflife.date API."""
    # Remove leading 'v' if present
    if version.startswith('v'):
        version = version[1:]
    
    # Extract major.minor or major version
    match = re.match(r'^(\d+\.\d+|\d+)', version)
    if match:
        return match.group(1)
    
    return version

def check_eol_status(package_name, package_version):
    """Check EOL status of a given package using EndOfLife API."""
    normalized_name = normalize_package_name(package_name)
    normalized_version = normalize_version(package_version)
    
    try:
        # First try to get all versions for this package
        response = requests.get(f"https://endoflife.date/api/{normalized_name}.json")
        
        if response.status_code == 200:
            data = response.json()
            for release in data:
                version = release.get("cycle", "")
                if str(version) == str(normalized_version):
                    return {
                        "cycle": version,
                        "latest": release.get("latest", "Unknown"),
                        "eol": release.get("eol", "Unknown"),
                        "support": release.get("support", "Unknown"),
                        "lts": release.get("lts", False),
                        "discontinued": release.get("discontinued", False),
                        "releaseDate": release.get("releaseDate", "Unknown"),
                        "link": release.get("link", None)
                    }
            
            # If we get here, we didn't find an exact match
            return None
        else:
            # Check if the product exists in the list of all products
            all_products_response = requests.get("https://endoflife.date/api/all.json")
            if all_products_response.status_code == 200:
                all_products = all_products_response.json()
                if normalized_name not in all_products:
                    print(f"Product '{normalized_name}' not found in endoflife.date database")
                    return None
            
            # Try individual lookup as fallback (replacing any slashes with dashes as per API spec)
            normalized_cycle = str(normalized_version).replace("/", "-")
            fallback_response = requests.get(f"https://endoflife.date/api/{normalized_name}/{normalized_cycle}.json")
            if fallback_response.status_code == 200:
                return fallback_response.json()
            
            print(f"No data found for {normalized_name} version {normalized_version}")
            return None
    except Exception as e:
        print(f"Error checking EOL status for {package_name} {package_version}: {e}")
        return None

def calculate_days_until_eol(eol_date):
    """Calculate days until end of life."""
    if eol_date == "Unknown" or eol_date is True or eol_date is False or eol_date is None:
        return None
    
    try:
        # Convert to datetime object
        eol_datetime = datetime.strptime(str(eol_date), "%Y-%m-%d")
        days_remaining = (eol_datetime - datetime.now()).days
        return days_remaining
    except ValueError:
        return None

def get_eol_status(days_until_eol):
    """Get EOL status based on days remaining."""
    if days_until_eol is None:
        return "Unknown"
    elif days_until_eol < 0:
        return "End of Life"
    elif days_until_eol <= 90:
        return "Critical (< 90 days)"
    elif days_until_eol <= 180:
        return "Warning (< 180 days)"
    elif days_until_eol <= 365:
        return "Attention (< 365 days)"
    else:
        return "OK"

def process_sbom(sbom_file, verbose=False):
    """Process the SBOM file and check EOL status for components."""
    with open(sbom_file, "r") as file:
        sbom_data = json.load(file)
    
    # Extract package names and versions from SBOM
    components = []
    
    # Identify format and handle accordingly
    if "components" in sbom_data:
        # CycloneDX or standard Syft format
        if verbose:
            print(f"Detected CycloneDX or standard Syft format with {len(sbom_data['components'])} components")
        for component in sbom_data.get("components", []):
            name = component.get("name")
            version = component.get("version")
            purl = component.get("purl", "N/A")
            type = component.get("type", "N/A")
            
            if name and version:
                components.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "type": type
                })
    
    elif "artifacts" in sbom_data:
        # Syft JSON format
        if verbose:
            print(f"Detected Syft JSON format with {len(sbom_data['artifacts'])} artifacts")
        for artifact in sbom_data.get("artifacts", []):
            name = artifact.get("name")
            version = artifact.get("version")
            purl = artifact.get("purl", "N/A")
            type = artifact.get("type", "N/A")
            
            if name and version:
                components.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "type": type
                })
    
    elif "packages" in sbom_data:
        # SPDX format
        if verbose:
            print(f"Detected SPDX format with {len(sbom_data['packages'])} packages")
        for package in sbom_data.get("packages", []):
            name = package.get("name")
            if not name:
                name = package.get("packageName")
            
            version = package.get("version")
            if not version:
                version = package.get("versionInfo")
                if not version:
                    version = package.get("packageVersion")
            
            purl = package.get("externalRefs", [])
            purl_value = "N/A"
            for ref in purl:
                if ref.get("referenceType") == "purl":
                    purl_value = ref.get("referenceLocator", "N/A")
                    break
            
            type = package.get("primaryPackagePurpose", "N/A")
            
            if name and version:
                components.append({
                    "name": name,
                    "version": version,
                    "purl": purl_value,
                    "type": type
                })
    
    # Fallback for other formats - try to find components or packages in any top-level array
    if not components:
        for key, value in sbom_data.items():
            if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
                if verbose:
                    print(f"Trying to extract components from '{key}' array with {len(value)} items")
                
                for item in value:
                    # Try common name and version keys
                    name = item.get("name") or item.get("packageName")
                    version = item.get("version") or item.get("versionInfo") or item.get("packageVersion")
                    purl = item.get("purl") or item.get("packageUrl") or "N/A"
                    type = item.get("type") or "N/A"
                    
                    if name and version:
                        components.append({
                            "name": name,
                            "version": version,
                            "purl": purl,
                            "type": type
                        })
    
    if verbose:
        print(f"Extracted {len(components)} components with name and version")
        if components:
            print("Sample components:")
            for comp in components[:5]:
                print(f"  - {comp['name']} {comp['version']}")
    
    return components

def main():
    parser = argparse.ArgumentParser(description="Check end-of-life status for software packages in an SBOM.")
    parser.add_argument("--target", help="Target to generate SBOM for (e.g., directory, image name)")
    parser.add_argument("--sbom", help="Path to existing SBOM JSON file")
    parser.add_argument("--output", default="eol_report.html", help="Output file for report")
    parser.add_argument("--format", choices=["html", "csv", "markdown", "text"], default="html", help="Output format")
    parser.add_argument("--api-url", default="https://endoflife.date", help="Base URL for the endoflife.date API")
    parser.add_argument("--alert-days", type=int, nargs=3, default=[90, 180, 365], 
                        help="Days thresholds for Critical, Warning, and Attention alerts (default: 90 180 365)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Print debug information about the SBOM")
    
    args = parser.parse_args()
    
    if args.debug and args.sbom:
        # Display debug information about the SBOM
        try:
            with open(args.sbom, "r") as file:
                sbom_data = json.load(file)
                
            print("\n=== SBOM Debug Information ===")
            print(f"File: {args.sbom}")
            print("Top-level keys:")
            for key in sbom_data.keys():
                if isinstance(sbom_data[key], list):
                    print(f"  - {key}: List with {len(sbom_data[key])} items")
                else:
                    print(f"  - {key}: {type(sbom_data[key]).__name__}")
            
            # Check for components
            if "components" in sbom_data:
                components = sbom_data["components"]
                print(f"\nFound {len(components)} components")
                if components:
                    print("First component example:")
                    print(json.dumps(components[0], indent=2))
            elif "artifacts" in sbom_data:
                artifacts = sbom_data["artifacts"]
                print(f"\nFound {len(artifacts)} artifacts")
                if artifacts:
                    print("First artifact example:")
                    print(json.dumps(artifacts[0], indent=2))
            elif "packages" in sbom_data:
                packages = sbom_data["packages"]
                print(f"\nFound {len(packages)} packages")
                if packages:
                    print("First package example:")
                    print(json.dumps(packages[0], indent=2))
            
            print("=== End Debug Information ===\n")
        except Exception as e:
            print(f"Error in debug mode: {e}")
    
    if not args.sbom and not args.target:
        parser.error("Either --sbom or --target must be provided")
    
    # Generate SBOM if target is specified
    if args.target:
        sbom_file = generate_syft_sbom(args.target)
    else:
        sbom_file = args.sbom
    
    components = process_sbom(sbom_file, args.verbose)
    
    if args.verbose:
        print(f"Processing {len(components)} components from SBOM")
    
    # Store results in a list
    results = []
    all_products = []
    
    # Try to get the list of all products supported by endoflife.date API
    try:
        all_products_response = requests.get(f"{args.api_url}/api/all.json")
        if all_products_response.status_code == 200:
            all_products = all_products_response.json()
            print(f"Found {len(all_products)} products supported by endoflife.date API")
    except Exception as e:
        print(f"Error getting supported products list: {e}")
    
    for component in components:
        name = component["name"]
        version = component["version"]
        purl = component["purl"]
        
        if args.verbose:
            print(f"Checking {name} version {version}")
            
        eol_data = check_eol_status(name, version)
        
        if eol_data:
            eol_date = eol_data.get("eol", "Unknown")
            support_date = eol_data.get("support", "Unknown")
            days_until_eol = calculate_days_until_eol(eol_date)
            days_until_support_end = calculate_days_until_eol(support_date) if support_date != "Unknown" else None
            status = get_eol_status(days_until_eol)
            
            # Create release date string
            release_date = eol_data.get("releaseDate", "Unknown")
            
            results.append({
                "Package": name,
                "Version": version,
                "Latest Version": eol_data.get("latest", "Unknown"),
                "Release Date": release_date,
                "Support End Date": support_date,
                "EOL Date": eol_date,
                "Days Until EOL": days_until_eol if days_until_eol is not None else "Unknown",
                "Status": status,
                "Package URL": purl,
                "LTS": "Yes" if eol_data.get("lts", False) else "No",
                "Discontinued": "Yes" if eol_data.get("discontinued", False) else "No",
                "Documentation": eol_data.get("link", "N/A")
            })
            
            if args.verbose:
                print(f"  ✓ Found EOL data: {status} - EOL date: {eol_date}")
        elif args.verbose:
            print(f"  ✗ No EOL data found")
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    if args.verbose:
        print(f"Found EOL data for {len(results)} of {len(components)} components")
    
    # Sort by status severity
    status_order = {
        "End of Life": 0,
        "Critical (< 90 days)": 1,
        "Warning (< 180 days)": 2,
        "Attention (< 365 days)": 3,
        "OK": 4,
        "Unknown": 5
    }
    
    if not df.empty:
        df["Status_Order"] = df["Status"].map(status_order)
        df = df.sort_values("Status_Order").drop("Status_Order", axis=1)
    
    # Generate output based on format
    if args.format == "html":
        # Generate HTML with colorized status cells
        # Define the HTML template using named placeholders to avoid formatting issues
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SBOM End of Life Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th {{ background-color: #f2f2f2; text-align: left; padding: 12px; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background-color: #f5f5f5; }}
                .summary {{ margin: 20px 0; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }}
                .eol {{ background-color: #ffcccc; }}
                .critical {{ background-color: #ffaaaa; }}
                .warning {{ background-color: #ffeeaa; }}
                .attention {{ background-color: #ffffcc; }}
                .ok {{ background-color: #ccffcc; }}
                .unknown {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>SBOM End of Life Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p>Total packages analyzed: {total}</p>
                <p>End of Life: {eol}</p>
                <p>Critical (&lt; 90 days): {critical}</p>
                <p>Warning (&lt; 180 days): {warning}</p>
                <p>Attention (&lt; 365 days): {attention}</p>
                <p>OK: {ok}</p>
                <p>Unknown: {unknown}</p>
            </div>
            {table}
            <p>Report generated on {date}</p>
        </body>
        </html>
        """
        
        if df.empty:
            html_content = html_template.format(
                total=0, eol=0, critical=0, warning=0, attention=0, ok=0, unknown=0,
                table="<p>No components found with EOL information.</p>",
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        else:
            # Create HTML table with colored status cells
            def style_status(row):
                status = row["Status"]
                if status == "End of Life":
                    return f'<td class="eol">{status}</td>'
                elif status == "Critical (< 90 days)":
                    return f'<td class="critical">{status}</td>'
                elif status == "Warning (< 180 days)":
                    return f'<td class="warning">{status}</td>'
                elif status == "Attention (< 365 days)":
                    return f'<td class="attention">{status}</td>'
                elif status == "OK":
                    return f'<td class="ok">{status}</td>'
                else:
                    return f'<td class="unknown">{status}</td>'
            
            # Count status categories
            status_counts = df["Status"].value_counts().to_dict()
            eol_count = status_counts.get("End of Life", 0)
            critical_count = status_counts.get("Critical (< 90 days)", 0)
            warning_count = status_counts.get("Warning (< 180 days)", 0)
            attention_count = status_counts.get("Attention (< 365 days)", 0)
            ok_count = status_counts.get("OK", 0)
            unknown_count = status_counts.get("Unknown", 0)
            
            # Generate HTML table
            table_rows = []
            table_rows.append("<table>")
            table_rows.append("<tr>")
            for col in df.columns:
                table_rows.append(f"<th>{col}</th>")
            table_rows.append("</tr>")
            
            for _, row in df.iterrows():
                table_rows.append("<tr>")
                for col in df.columns:
                    if col == "Status":
                        table_rows.append(style_status(row))
                    else:
                        table_rows.append(f"<td>{row[col]}</td>")
                table_rows.append("</tr>")
            table_rows.append("</table>")
            
            html_content = html_template.format(
                total=len(df),
                eol=eol_count,
                critical=critical_count,
                warning=warning_count,
                attention=attention_count,
                ok=ok_count,
                unknown=unknown_count,
                table="\n".join(table_rows),
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        
        with open(args.output, "w") as file:
            file.write(html_content)
        
        print(f"HTML report saved to {args.output}")
    
    elif args.format == "csv":
        csv_file = args.output if args.output.endswith(".csv") else args.output + ".csv"
        df.to_csv(csv_file, index=False)
        print(f"CSV report saved to {csv_file}")
    
    elif args.format == "markdown":
        md_file = args.output if args.output.endswith(".md") else args.output + ".md"
        
        with open(md_file, "w") as file:
            file.write("# SBOM End of Life Report\n\n")
            
            # Summary section
            file.write("## Summary\n\n")
            file.write(f"Total packages analyzed: {len(df)}\n\n")
            
            if not df.empty:
                status_counts = df["Status"].value_counts().to_dict()
                file.write(f"- End of Life: {status_counts.get('End of Life', 0)}\n")
                file.write(f"- Critical (< 90 days): {status_counts.get('Critical (< 90 days)', 0)}\n")
                file.write(f"- Warning (< 180 days): {status_counts.get('Warning (< 180 days)', 0)}\n")
                file.write(f"- Attention (< 365 days): {status_counts.get('Attention (< 365 days)', 0)}\n")
                file.write(f"- OK: {status_counts.get('OK', 0)}\n")
                file.write(f"- Unknown: {status_counts.get('Unknown', 0)}\n\n")
            
            # Data table
            file.write("## Package Details\n\n")
            if df.empty:
                file.write("No components found with EOL information.\n")
            else:
                file.write(df.to_markdown(index=False))
            
            file.write(f"\n\nReport generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"Markdown report saved to {md_file}")
    
    else:  # text format
        txt_file = args.output if args.output.endswith(".txt") else args.output + ".txt"
        
        with open(txt_file, "w") as file:
            file.write("SBOM End of Life Report\n")
            file.write("======================\n\n")
            
            # Summary section
            file.write("Summary:\n")
            file.write(f"Total packages analyzed: {len(df)}\n\n")
            
            if not df.empty:
                status_counts = df["Status"].value_counts().to_dict()
                file.write(f"End of Life: {status_counts.get('End of Life', 0)}\n")
                file.write(f"Critical (< 90 days): {status_counts.get('Critical (< 90 days)', 0)}\n")
                file.write(f"Warning (< 180 days): {status_counts.get('Warning (< 180 days)', 0)}\n")
                file.write(f"Attention (< 365 days): {status_counts.get('Attention (< 365 days)', 0)}\n")
                file.write(f"OK: {status_counts.get('OK', 0)}\n")
                file.write(f"Unknown: {status_counts.get('Unknown', 0)}\n\n")
            
            # Data table
            file.write("Package Details:\n")
            if df.empty:
                file.write("No components found with EOL information.\n")
            else:
                file.write(tabulate(df, headers='keys', tablefmt='grid'))
            
            file.write(f"\n\nReport generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"Text report saved to {txt_file}")
    
    # Print summary to console
    print("\nSummary:")
    print(f"Total packages analyzed: {len(df)}")
    
    if not df.empty:
        status_counts = df["Status"].value_counts().to_dict()
        print(f"End of Life: {status_counts.get('End of Life', 0)}")
        print(f"Critical (< 90 days): {status_counts.get('Critical (< 90 days)', 0)}")
        print(f"Warning (< 180 days): {status_counts.get('Warning (< 180 days)', 0)}")
        print(f"Attention (< 365 days): {status_counts.get('Attention (< 365 days)', 0)}")
        print(f"OK: {status_counts.get('OK', 0)}")
        print(f"Unknown: {status_counts.get('Unknown', 0)}")

if __name__ == "__main__":
    main()