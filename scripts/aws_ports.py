import boto3
import argparse

def write_to_markdown(file, content):
    with open(file, "a") as f:
        f.write(content + "\n")

def format_table(headers, rows):
    """Formats data as a Markdown table."""
    table = f"| {' | '.join(headers)} |\n"
    table += f"| {' | '.join(['---'] * len(headers))} |\n"
    for row in rows:
        table += f"| {' | '.join(str(cell) for cell in row)} |\n"
    return table

def list_security_group_rules(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "# Security Group Rules")
    try:
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            write_to_markdown(markdown_file, f"## Security Group: {sg['GroupName']} ({sg['GroupId']})")
            rows = []
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 'All')
                to_port = rule.get('ToPort', 'All')
                protocol = rule.get('IpProtocol', 'All')
                
                rows.append([
                    sg['GroupName'],
                    protocol,
                    str(from_port),
                    str(to_port),
                ])
                all_ports.append([sg['GroupName'], protocol, str(from_port)])
            if rows:
                write_to_markdown(markdown_file, format_table(["Group Name", "Protocol", "From Port", "To Port"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing security groups: {str(e)}")

def list_alb_ports(elbv2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# ALB Listener Ports")
    try:
        load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
        rows = []
        for lb in load_balancers:
            listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])['Listeners']
            for listener in listeners:
                rows.append([
                    lb['LoadBalancerName'],
                    listener['Protocol'],
                    str(listener['Port']),
                ])
                all_ports.append([lb['LoadBalancerName'], listener['Protocol'], str(listener['Port'])])
        if rows:
            write_to_markdown(markdown_file, format_table(["Load Balancer Name", "Protocol", "Port"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing ALB ports: {str(e)}")

def list_ecs_ports(ecs_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# ECS Task Definitions and Ports")
    try:
        clusters = ecs_client.list_clusters()['clusterArns']
        rows = []
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster)['taskArns']
            if tasks:  # Only process if there are tasks
                for task in tasks:
                    task_desc = ecs_client.describe_tasks(cluster=cluster, tasks=[task])['tasks'][0]
                    task_def_arn = task_desc['taskDefinitionArn']
                    task_definition = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                    container_defs = task_definition['taskDefinition']['containerDefinitions']
                    for container in container_defs:
                        for port in container.get('portMappings', []):
                            rows.append([
                                container['name'],
                                port.get('protocol', 'unknown'),
                                str(port.get('containerPort', 'unknown')),
                            ])
                            all_ports.append([container['name'], port.get('protocol', 'unknown'), 
                                            str(port.get('containerPort', 'unknown'))])
        if rows:
            write_to_markdown(markdown_file, format_table(["Container Name", "Protocol", "Port"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing ECS ports: {str(e)}")

def list_nacl_rules(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# Network ACL Rules")
    try:
        nacls = ec2_client.describe_network_acls()['NetworkAcls']
        rows = []
        for nacl in nacls:
            for entry in nacl['Entries']:
                direction = "Inbound" if not entry['Egress'] else "Outbound"
                port_range = entry.get('PortRange', {})
                rows.append([
                    nacl['NetworkAclId'],
                    direction,
                    str(entry.get('Protocol', 'All')),
                    str(port_range.get('From', 'All')),
                    str(port_range.get('To', 'All')),
                ])
                all_ports.append([nacl['NetworkAclId'], str(entry.get('Protocol', 'All')), 
                                str(port_range.get('From', 'All'))])
        if rows:
            write_to_markdown(markdown_file, format_table(["NACL ID", "Direction", "Protocol", "From Port", "To Port"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing NACL rules: {str(e)}")

def list_nat_gateways(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# NAT Gateways")
    try:
        nat_gateways = ec2_client.describe_nat_gateways()['NatGateways']
        rows = []
        for nat in nat_gateways:
            if nat['NatGatewayAddresses']:  # Check if there are addresses
                rows.append([
                    nat['NatGatewayId'],
                    nat['NatGatewayAddresses'][0].get('PublicIp', 'N/A'),
                    "Outbound",
                ])
                all_ports.append([nat['NatGatewayId'], "Outbound", "N/A"])
        if rows:
            write_to_markdown(markdown_file, format_table(["NAT Gateway ID", "Public IP", "Direction"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing NAT gateways: {str(e)}")

def list_vpc_endpoints(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# VPC Endpoints")
    try:
        endpoints = ec2_client.describe_vpc_endpoints()['VpcEndpoints']
        rows = []
        for endpoint in endpoints:
            rows.append([
                endpoint['VpcEndpointId'],
                endpoint['ServiceName'],
                "N/A",
            ])
            all_ports.append([endpoint['VpcEndpointId'], "N/A", "N/A"])
        if rows:
            write_to_markdown(markdown_file, format_table(["Endpoint ID", "Service Name", "Port"], rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing VPC endpoints: {str(e)}")

def list_all_ports(markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# Consolidated Ports Table")
    try:
        unique_ports = {tuple(port) for port in all_ports}
        rows = sorted(list(unique_ports))
        headers = ["Resource Name", "Protocol", "Port"]
        write_to_markdown(markdown_file, format_table(headers, rows))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error creating consolidated ports table: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="AWS Port and Protocol Analysis")
    parser.add_argument("--region", required=True, help="AWS region (e.g., us-east-1)")
    parser.add_argument("--profile", required=False, help="AWS profile name")
    parser.add_argument("--output", default="vpc_ports_and_protocols.md", 
                       help="Output markdown file name (default: vpc_ports_and_protocols.md)")

    args = parser.parse_args()

    try:
        # Set AWS profile if provided
        if args.profile:
            boto3.setup_default_session(profile_name=args.profile)

        # Initialize AWS clients
        ec2_client = boto3.client('ec2', region_name=args.region)
        elbv2_client = boto3.client('elbv2', region_name=args.region)
        ecs_client = boto3.client('ecs', region_name=args.region)

        # Clear and initialize markdown file
        markdown_file = args.output
        open(markdown_file, "w").close()

        # Collect data and write to Markdown
        all_ports = []
        list_security_group_rules(ec2_client, markdown_file, all_ports)
        list_alb_ports(elbv2_client, markdown_file, all_ports)
        list_ecs_ports(ecs_client, markdown_file, all_ports)
        list_nacl_rules(ec2_client, markdown_file, all_ports)
        list_nat_gateways(ec2_client, markdown_file, all_ports)
        list_vpc_endpoints(ec2_client, markdown_file, all_ports)

        # Consolidated table at the end
        list_all_ports(markdown_file, all_ports)

        print(f"Documentation successfully saved to {markdown_file}")

    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()