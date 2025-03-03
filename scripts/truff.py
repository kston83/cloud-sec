import os
import subprocess
from datetime import datetime
import argparse

# Define the default output directory
OUTPUT_DIR = os.path.expanduser("~/auto_scans")

# Ensure the output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Get the current date for organizing the scan results
current_date = datetime.now().strftime("%Y-%m-%d")

def update_git_repo(repo_path, branch):
    """
    Updates the Git repository to the latest version and checks out the specified branch.
    """
    try:
        print(f"Updating repository at: {repo_path}")
        subprocess.run(["git", "-C", repo_path, "fetch"], check=True)
        if branch:
            print(f"Checking out branch: {branch}")
            subprocess.run(["git", "-C", repo_path, "checkout", branch], check=True)
        subprocess.run(["git", "-C", repo_path, "pull"], check=True)
        print(f"Repository updated successfully: {repo_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error updating repository at {repo_path}: {e}")

def run_trufflehog_scan(repo_path, project_name):
    """
    Runs the TruffleHog scan for the given repository and saves the output.
    """
    repo_name = os.path.basename(repo_path.rstrip(os.sep))
    
    # Create a subdirectory for today's date
    date_output_dir = os.path.join(OUTPUT_DIR, current_date, project_name)
    os.makedirs(date_output_dir, exist_ok=True)
    
    # Define the output file path
    output_file = os.path.join(date_output_dir, f"trufflehog_{repo_name}_{current_date}.html")

    command = [
        "trufflehog3",
        "--zero",
        "--format", "html",
        repo_path,
        "--output", output_file,
        "--no-entropy",
        "--no-history",
        "--ignore-nosecret",
        "--context", "0"
    ]
    try:
        print(f"Running TruffleHog scan for: {repo_path}")
        subprocess.run(command, check=True)
        print(f"Results saved to: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error while scanning {repo_path}: {e}")

def scan_repositories(top_level_dir, branch):
    """
    Scans Git repositories. Can handle both:
    1. A directory containing multiple git repos in subdirectories
    2. A single git repository
    """
    print(f"Starting scan with directory: {top_level_dir} and branch: {branch}")
    
    if not os.path.exists(top_level_dir):
        print(f"Error: Directory {top_level_dir} does not exist")
        return

    # Check if the provided path is itself a git repository
    if os.path.isdir(top_level_dir) and ".git" in os.listdir(top_level_dir):
        print(f"Found single Git repository: {top_level_dir}")
        repo_name = os.path.basename(top_level_dir.rstrip(os.sep))
        update_git_repo(top_level_dir, branch)
        run_trufflehog_scan(top_level_dir, repo_name)
        return

    # If not a single repo, scan for repositories in subdirectories
    for project_name in os.listdir(top_level_dir):
        project_path = os.path.join(top_level_dir, project_name)
        if os.path.isdir(project_path):
            for repo_name in os.listdir(project_path):
                repo_path = os.path.join(project_path, repo_name)
                if os.path.isdir(repo_path) and ".git" in os.listdir(repo_path):
                    print(f"Found Git repository: {repo_name} under {project_name}")
                    update_git_repo(repo_path, branch)
                    run_trufflehog_scan(repo_path, project_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run TruffleHog scans on Git repositories.")
    parser.add_argument("--directory", "-d", 
                       default=os.path.expanduser("~/cms-repos"),
                       help="Top-level directory containing Git repositories (default: ~/cms-repos)")
    parser.add_argument("--branch", "-b",
                       help="Specify a branch to scan (default: current branch)",
                       default=None)
    args = parser.parse_args()
    
    print(f"Arguments received: directory={args.directory}, branch={args.branch}")
    scan_repositories(args.directory, args.branch)