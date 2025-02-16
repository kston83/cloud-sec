#!/usr/bin/env python3
import boto3
import argparse
from tabulate import tabulate

def get_instances(ec2_client):
    """
    Retrieve EC2 instances details and collect their instance IDs, public IPs,
    private IPs, and AMI IDs.
    """
    instance_details = []
    ami_ids = set()

    response = ec2_client.describe_instances()
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instance_id = instance.get('InstanceId')
            public_ip = instance.get('PublicIpAddress', 'N/A')
            private_ip = instance.get('PrivateIpAddress', 'N/A')
            image_id = instance.get('ImageId', 'N/A')
            instance_details.append({
                'InstanceId': instance_id,
                'PublicIp': public_ip,
                'PrivateIp': private_ip,
                'ImageId': image_id
            })
            if image_id != 'N/A':
                ami_ids.add(image_id)
    return instance_details, list(ami_ids)

def get_ami_os_info(ec2_client, ami_ids):
    """
    Retrieve AMI details for the provided AMI IDs.
    Returns a dictionary mapping each AMI ID to its OS info (using the AMI's Name field).
    """
    ami_os_map = {}
    if not ami_ids:
        return ami_os_map

    try:
        response = ec2_client.describe_images(ImageIds=ami_ids)
    except Exception as e:
        print(f"Error retrieving AMI details: {e}")
        return ami_os_map

    for image in response.get('Images', []):
        image_id = image.get('ImageId')
        # Using the Name field to indicate OS info.
        os_info = image.get('Name', 'Unknown')
        ami_os_map[image_id] = os_info
    return ami_os_map

def main(profile, region, outfile):
    # Create a boto3 session using the provided profile and region.
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2_client = session.client('ec2')

    # Retrieve EC2 instances and unique AMI IDs.
    instances, ami_ids = get_instances(ec2_client)
    ami_os_map = get_ami_os_info(ec2_client, ami_ids)

    # Prepare data for the table.
    table_data = []
    headers = ['Instance ID', 'Public IP', 'Private IP', 'AMI ID', 'OS Info']
    for inst in instances:
        ami_id = inst['ImageId']
        os_info = ami_os_map.get(ami_id, 'Unknown')
        table_data.append([inst['InstanceId'], inst['PublicIp'], inst['PrivateIp'], ami_id, os_info])

    # Generate the table in grid format.
    table_output = tabulate(table_data, headers=headers, tablefmt='grid')

    # Print to console.
    print(table_output)

    # If an output file is provided, write the output there.
    if outfile:
        try:
            with open(outfile, 'w') as f:
                f.write(table_output)
            print(f"\nReport written to: {outfile}")
        except Exception as e:
            print(f"Error writing to file {outfile}: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Report EC2 Instances with IPs and OS Info'
    )
    parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    parser.add_argument('--region', required=True, help='AWS region (e.g., us-east-1)')
    parser.add_argument('--outfile', help='Path to output file (optional)')
    args = parser.parse_args()
    main(args.profile, args.region, args.outfile)
