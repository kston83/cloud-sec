import boto3
import argparse
from datetime import datetime
import re

def write_to_markdown(file, content):
    with open(file, "a") as f:
        f.write(content + "\n")

def format_table(headers, rows):
    """Formats data as a Markdown table with column alignment."""
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    # Create header row with padding
    header = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths)) + " |"
    # Create alignment row (left-align for text, right-align for numbers)
    separator = "|"
    for i, h in enumerate(headers):
        separator += f" {'---' if 'ID' not in h and 'Port' not in h else '---:'} |"
    
    # Create data rows
    data_rows = []
    for row in rows:
        formatted_row = "| " + " | ".join(str(cell).ljust(w) for cell, w in zip(row, col_widths)) + " |"
        data_rows.append(formatted_row)
    
    return "\n".join([header, separator] + data_rows) + "\n"

def get_protocol_for_service(resource_name, protocol, port, service_type=''):
    """
    Enhanced protocol detection based on service type, port, and resource name
    """
    # Expanded common port to protocol mappings
    common_ports = {
        # Web protocols
        '80': 'HTTP',
        '443': 'HTTPS',
        '8080': 'HTTP',
        '8443': 'HTTPS',
        # Database protocols
        '3306': 'MySQL/Aurora',
        '5432': 'PostgreSQL',
        '1433': 'MSSQL',
        '1521': 'Oracle',
        '27017': 'MongoDB',
        '6379': 'Redis',
        '11211': 'Memcached',
        # Mail protocols
        '25': 'SMTP',
        '465': 'SMTPS',
        '587': 'SMTP/TLS',
        '110': 'POP3',
        '995': 'POP3S',
        '143': 'IMAP',
        '993': 'IMAPS',
        # Directory services
        '389': 'LDAP',
        '636': 'LDAPS',
        '88': 'Kerberos',
        '464': 'Kerberos',
        # File transfer
        '20': 'FTP-Data',
        '21': 'FTP-Control',
        '22': 'SSH/SFTP',
        '69': 'TFTP',
        # Name services
        '53': 'DNS',
        '137': 'NetBIOS-NS',
        '138': 'NetBIOS-DGM',
        '139': 'NetBIOS-SSN',
        # Management protocols
        '161': 'SNMP',
        '162': 'SNMP-Trap',
        '445': 'SMB',
        '514': 'Syslog',
        # Messaging protocols
        '1883': 'MQTT',
        '5671': 'AMQP',
        '5672': 'AMQP',
        # Container and orchestration
        '2375': 'Docker',
        '2376': 'Docker-TLS',
        '2379': 'etcd',
        '2380': 'etcd',
        '6443': 'Kubernetes-API',
        '10250': 'Kubelet',
        # AWS specific
        '1150': 'RDS-Proxy',
        '1153': 'RDS-IAM',
        '2049': 'NFS/EFS'
    }

    # Service-specific protocol detection
    if service_type == 'alb':
        if port == '80':
            return 'HTTP'
        elif port == '443':
            return 'HTTPS'
        return 'HTTP/HTTPS'
    
    elif service_type == 'rds':
        if 'aurora' in resource_name.lower():
            return 'MySQL/Aurora'
        elif 'postgres' in resource_name.lower():
            return 'PostgreSQL'
        elif 'mysql' in resource_name.lower():
            return 'MySQL'
        elif 'sqlserver' in resource_name.lower():
            return 'MSSQL'
        elif 'oracle' in resource_name.lower():
            return 'Oracle'
    
    elif service_type == 'ecs':
        if 'nginx' in resource_name.lower() or 'web' in resource_name.lower():
            return 'HTTP/HTTPS'
        elif 'api' in resource_name.lower():
            return 'HTTP/HTTPS'
        elif any(db in resource_name.lower() for db in ['mysql', 'postgres', 'mongo', 'redis']):
            return 'DB-Protocol'
    
    elif service_type == 'nacl':
        if protocol == '-1':
            return 'All Traffic'
        elif protocol.isdigit():
            nacl_protocols = {
                '6': 'TCP',
                '17': 'UDP',
                '1': 'ICMP',
                '58': 'ICMPv6'
            }
            return nacl_protocols.get(protocol, f'Protocol {protocol}')
    
    # VPC Endpoint specific handling
    if 's3' in resource_name.lower():
        return 'HTTPS/S3'
    elif 'dynamodb' in resource_name.lower():
        return 'HTTPS/DynamoDB'
    
    # Check if it's a well-known port
    if str(port) in common_ports:
        return common_ports[str(port)]
    
    # Handle generic protocol strings
    if protocol:
        protocol = str(protocol).upper()
        if protocol == '-1':
            return 'All Traffic'
        elif protocol in ['TCP', 'UDP', 'ICMP']:
            return protocol
    
    return protocol or 'Unknown'

def get_port_range_display(from_port, to_port):
    """Format port range for display"""
    if from_port == to_port:
        return str(from_port)
    elif from_port == -1 or to_port == -1:
        return 'All'
    else:
        return f"{from_port}-{to_port}"

def list_rds_instances(rds_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# RDS Instances and Ports")
    try:
        instances = rds_client.describe_db_instances()['DBInstances']
        rows = []
        for instance in instances:
            # Get the standard port for the instance
            port = instance['Endpoint']['Port']
            protocol = get_protocol_for_service(
                instance['DBInstanceIdentifier'],
                instance['Engine'],
                str(port),
                'rds'
            )
            
            # Get security groups associated with the RDS instance
            security_groups = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]
            
            # Get subnet group
            subnet_group = instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A')
            
            # Get encryption status
            encryption_status = 'Enabled' if instance.get('StorageEncrypted', False) else 'Disabled'
            
            rows.append([
                instance['DBInstanceIdentifier'],
                protocol,
                str(port),
                instance['Engine'],
                instance['EngineVersion'],
                subnet_group,
                encryption_status,
                ', '.join(security_groups) or 'N/A'
            ])
            all_ports.append([instance['DBInstanceIdentifier'], protocol, str(port)])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["Instance ID", "Protocol", "Port", "Engine", "Version", "Subnet Group", "Encryption", "Security Groups"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing RDS instances: {str(e)}")

def list_waf_configs(waf_client, wafregional_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# WAF Configurations")
    try:
        # Define ports at the beginning of the function
        ports = ['80', '443']  # Default ports for web traffic
        
        # Get WAF ACLs
        web_acls = waf_client.list_web_acls()['WebACLs']
        rows = []
        
        for acl in web_acls:
            # Get the full ACL details
            acl_details = waf_client.get_web_acl(WebACLId=acl['WebACLId'])['WebACL']
            
            # Get associated resources (ALBs, etc.)
            resources = waf_client.list_resources_for_web_acl(
                WebACLId=acl['WebACLId']
            )['ResourceArns']
            
            # Get rules
            rules = [rule['RuleId'] for rule in acl_details.get('Rules', [])]
            rule_names = []
            for rule_id in rules:
                try:
                    rule_details = waf_client.get_rule(RuleId=rule_id)['Rule']
                    rule_names.append(rule_details['Name'])
                except:
                    continue
            
            # Add entries for both ports
            for port in ports:
                rows.append([
                    acl['Name'],
                    'HTTP/HTTPS',
                    port,
                    'Global',
                    ', '.join(rule_names) or 'No rules',
                    ', '.join(resources) or 'N/A'
                ])
                all_ports.append([f"WAF-{acl['Name']}", 'HTTP/HTTPS', port])
        
        # Get Regional WAF ACLs
        try:
            regional_web_acls = wafregional_client.list_web_acls()['WebACLs']
            for acl in regional_web_acls:
                acl_details = wafregional_client.get_web_acl(WebACLId=acl['WebACLId'])['WebACL']
                
                resources = wafregional_client.list_resources_for_web_acl(
                    WebACLId=acl['WebACLId']
                )['ResourceArns']
                
                # Get rules
                rules = [rule['RuleId'] for rule in acl_details.get('Rules', [])]
                rule_names = []
                for rule_id in rules:
                    try:
                        rule_details = wafregional_client.get_rule(RuleId=rule_id)['Rule']
                        rule_names.append(rule_details['Name'])
                    except:
                        continue
                
                # Add entries for both ports
                for port in ports:
                    rows.append([
                        acl['Name'],
                        'HTTP/HTTPS',
                        port,
                        'Regional',
                        ', '.join(rule_names) or 'No rules',
                        ', '.join(resources) or 'N/A'
                    ])
                    all_ports.append([f"WAF-Regional-{acl['Name']}", 'HTTP/HTTPS', port])
        except Exception as e:
            write_to_markdown(markdown_file, f"Error listing regional WAF configurations: {str(e)}")
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["ACL Name", "Protocol", "Port", "Scope", "Rules", "Associated Resources"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing WAF configurations: {str(e)}")

def list_security_group_rules(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "# Security Group Rules")
    try:
        security_groups = ec2_client.describe_security_groups()['SecurityGroups']
        for sg in security_groups:
            write_to_markdown(markdown_file, f"## Security Group: {sg['GroupName']} ({sg['GroupId']})")
            
            # Separate inbound and outbound rules
            inbound_rows = []
            outbound_rows = []
            
            # Process inbound rules
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', -1)
                to_port = rule.get('ToPort', -1)
                protocol = rule.get('IpProtocol', '-1')
                
                port_range = get_port_range_display(from_port, to_port)
                protocol_display = get_protocol_for_service(sg['GroupName'], protocol, port_range, 'security_group')
                
                cidr_ranges = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
                cidr_display = ', '.join(cidr_ranges) if cidr_ranges else 'All'
                
                inbound_rows.append([
                    sg['GroupName'],
                    protocol_display,
                    port_range,
                    cidr_display
                ])
                
                all_ports.append([sg['GroupName'], protocol_display, port_range])
            
            # Process outbound rules
            for rule in sg.get('IpPermissionsEgress', []):
                from_port = rule.get('FromPort', -1)
                to_port = rule.get('ToPort', -1)
                protocol = rule.get('IpProtocol', '-1')
                
                port_range = get_port_range_display(from_port, to_port)
                protocol_display = get_protocol_for_service(sg['GroupName'], protocol, port_range, 'security_group')
                
                cidr_ranges = [ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])]
                cidr_display = ', '.join(cidr_ranges) if cidr_ranges else 'All'
                
                outbound_rows.append([
                    sg['GroupName'],
                    protocol_display,
                    port_range,
                    cidr_display
                ])
            
            if inbound_rows:
                write_to_markdown(markdown_file, "\n### Inbound Rules")
                write_to_markdown(markdown_file, format_table(
                    ["Group Name", "Protocol", "Ports", "CIDR"], 
                    sorted(inbound_rows)
                ))
            
            if outbound_rows:
                write_to_markdown(markdown_file, "\n### Outbound Rules")
                write_to_markdown(markdown_file, format_table(
                    ["Group Name", "Protocol", "Ports", "CIDR"],
                    sorted(outbound_rows)
                ))
                
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing security groups: {str(e)}")

def list_alb_ports(elbv2_client, waf_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# ALB Listener Ports")
    try:
        load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
        rows = []
        for lb in load_balancers:
            listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])['Listeners']
            
            # Get WAF association if any
            try:
                waf_association = waf_client.get_web_acl_for_resource(
                    ResourceArn=lb['LoadBalancerArn']
                )
                waf_acl = waf_association.get('WebACLSummary', {}).get('Name', 'N/A')
            except Exception:
                waf_acl = 'N/A'
            
            for listener in listeners:
                protocol = get_protocol_for_service(
                    lb['LoadBalancerName'],
                    listener['Protocol'],
                    str(listener['Port']),
                    'alb'
                )
                
                # Get target group details
                target_groups = []
                if 'DefaultActions' in listener:
                    for action in listener['DefaultActions']:
                        if action['Type'] == 'forward' and 'TargetGroupArn' in action:
                            target_group = action['TargetGroupArn'].split('/')[-1]
                            target_groups.append(target_group)
                
                rows.append([
                    lb['LoadBalancerName'],
                    protocol,
                    str(listener['Port']),
                    listener.get('SslPolicy', 'N/A') if protocol == 'HTTPS' else 'N/A',
                    waf_acl,
                    ', '.join(target_groups) if target_groups else 'N/A'
                ])
                all_ports.append([lb['LoadBalancerName'], protocol, str(listener['Port'])])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["Load Balancer Name", "Protocol", "Port", "SSL Policy", "WAF ACL", "Target Groups"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing ALB ports: {str(e)}")

def list_nacl_rules(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# Network ACL Rules")
    try:
        nacls = ec2_client.describe_network_acls()['NetworkAcls']
        rows = []
        for nacl in nacls:
            for entry in nacl['Entries']:
                direction = "Inbound" if not entry['Egress'] else "Outbound"
                port_range = entry.get('PortRange', {})
                from_port = port_range.get('From', 'All')
                to_port = port_range.get('To', 'All')
                port_display = get_port_range_display(from_port, to_port)
                
                protocol = get_protocol_for_service(
                    nacl['NetworkAclId'],
                    str(entry.get('Protocol', '-1')),
                    str(from_port),
                    'nacl'
                )
                
                rows.append([
                    nacl['NetworkAclId'],
                    direction,
                    protocol,
                    port_display,
                    entry.get('RuleAction', 'N/A'),
                    entry.get('CidrBlock', 'N/A')
                ])
                all_ports.append([
                    f"NACL-{nacl['NetworkAclId']}", 
                    protocol, 
                    port_display
                ])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["NACL ID", "Direction", "Protocol", "Ports", "Action", "CIDR"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing NACL rules: {str(e)}")

def list_nat_gateways(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# NAT Gateways")
    try:
        nat_gateways = ec2_client.describe_nat_gateways()['NatGateways']
        rows = []
        for nat in nat_gateways:
            if nat['NatGatewayAddresses']:
                public_ip = nat['NatGatewayAddresses'][0].get('PublicIp', 'N/A')
                private_ip = nat['NatGatewayAddresses'][0].get('PrivateIp', 'N/A')
                
                # NAT Gateways use specific ports for different protocols
                nat_ports = [
                    ('TCP', '1024-65535'),
                    ('UDP', '1024-65535'),
                    ('ICMP', 'All')
                ]
                
                for protocol, port_range in nat_ports:
                    rows.append([
                        nat['NatGatewayId'],
                        public_ip,
                        private_ip,
                        protocol,
                        port_range,
                        nat['State']
                    ])
                    all_ports.append([
                        f"NAT-{nat['NatGatewayId']}", 
                        protocol, 
                        port_range
                    ])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["NAT Gateway ID", "Public IP", "Private IP", "Protocol", "Ports", "State"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing NAT gateways: {str(e)}")

def list_ecs_ports(ecs_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# ECS Task Definitions and Ports")
    try:
        clusters = ecs_client.list_clusters()['clusterArns']
        rows = []
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster)['taskArns']
            if tasks:
                for task in tasks:
                    task_desc = ecs_client.describe_tasks(cluster=cluster, tasks=[task])['tasks'][0]
                    task_def_arn = task_desc['taskDefinitionArn']
                    task_definition = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                    container_defs = task_definition['taskDefinition']['containerDefinitions']
                    
                    for container in container_defs:
                        for port in container.get('portMappings', []):
                            protocol = get_protocol_for_service(
                                container['name'],
                                port.get('protocol', 'unknown'),
                                str(port.get('containerPort', 'unknown')),
                                'ecs'
                            )
                            
                            rows.append([
                                container['name'],
                                protocol,
                                str(port.get('containerPort', 'unknown')),
                                str(port.get('hostPort', 'dynamic'))
                            ])
                            all_ports.append([
                                container['name'],
                                protocol,
                                str(port.get('containerPort', 'unknown'))
                            ])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["Container Name", "Protocol", "Container Port", "Host Port"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing ECS ports: {str(e)}")

def list_vpc_endpoints(ec2_client, markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# VPC Endpoints")
    try:
        endpoints = ec2_client.describe_vpc_endpoints()['VpcEndpoints']
        rows = []
        for endpoint in endpoints:
            protocol = get_protocol_for_service(
                endpoint['ServiceName'],
                'TCP',  # VPC Endpoints typically use TCP
                '443',  # Most AWS services use HTTPS (port 443)
                'vpc_endpoint'
            )
            
            security_groups = [sg['GroupId'] for sg in endpoint.get('Groups', [])]
            
            rows.append([
                endpoint['VpcEndpointId'],
                endpoint['VpcEndpointType'],
                endpoint['ServiceName'],
                protocol,
                endpoint['State'],
                ', '.join(security_groups) if security_groups else 'N/A'
            ])
            
            # Only add to all_ports if it's an interface endpoint (Gateway endpoints don't have ports)
            if endpoint['VpcEndpointType'] == 'Interface':
                all_ports.append([
                    f"VPCe-{endpoint['VpcEndpointId']}", 
                    protocol, 
                    '443'
                ])
        
        if rows:
            write_to_markdown(markdown_file, format_table(
                ["Endpoint ID", "Type", "Service", "Protocol", "State", "Security Groups"],
                sorted(rows)
            ))
    except Exception as e:
        write_to_markdown(markdown_file, f"Error listing VPC endpoints: {str(e)}")


def list_all_ports(markdown_file, all_ports):
    write_to_markdown(markdown_file, "\n# Consolidated Ports Table")
    try:
        # Create a mapping of port combinations for deduplication
        port_map = {}
        for resource, protocol, port in all_ports:
            key = (port, protocol)
            if key not in port_map:
                port_map[key] = set()
            port_map[key].add(resource)
        
        # Create rows with consolidated information
        rows = []
        for (port, protocol), resources in sorted(port_map.items()):
            rows.append([
                ', '.join(sorted(resources)),
                protocol,
                port,
                len(resources)  # Add count of resources using this port/protocol combination
            ])
        
        write_to_markdown(markdown_file, format_table(
            ["Resources", "Protocol", "Port", "Usage Count"],
            sorted(rows, key=lambda x: (-x[3], x[2]))  # Sort by usage count (desc) then port
        ))
        
        # Add summary statistics
        total_ports = len(port_map)
        total_resources = sum(len(resources) for resources in port_map.values())
        write_to_markdown(markdown_file, f"\n### Summary Statistics")
        write_to_markdown(markdown_file, f"- Total unique port/protocol combinations: {total_ports}")
        write_to_markdown(markdown_file, f"- Total resource port mappings: {total_resources}")
        
    except Exception as e:
        write_to_markdown(markdown_file, f"Error creating consolidated ports table: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="AWS Port and Protocol Analysis")
    parser.add_argument("--region", required=True, help="AWS region (e.g., us-east-1)")
    parser.add_argument("--profile", required=False, help="AWS profile name")
    parser.add_argument("--output", default="vpc_ports_and_protocols.md", 
                       help="Output markdown file name (default: vpc_ports_and_protocols.md)")
    parser.add_argument("--tags", action="store_true", 
                       help="Include resource tags in the analysis")
    parser.add_argument("--exclude-services", nargs='+', 
                       help="Services to exclude (e.g., alb ecs nacl rds waf)")
    parser.add_argument("--waf-only", action="store_true",
                       help="Only analyze WAF and associated resources")

    args = parser.parse_args()

    try:
        # Set AWS profile if provided
        if args.profile:
            boto3.setup_default_session(profile_name=args.profile)

        # Initialize AWS clients with error handling
        clients = {}
        try:
            clients['ec2'] = boto3.client('ec2', region_name=args.region)
            clients['elbv2'] = boto3.client('elbv2', region_name=args.region)
            clients['ecs'] = boto3.client('ecs', region_name=args.region)
            clients['rds'] = boto3.client('rds', region_name=args.region)
            clients['waf'] = boto3.client('waf', region_name=args.region)
            clients['wafv2'] = boto3.client('wafv2', region_name=args.region)
            clients['wafregional'] = boto3.client('waf-regional', region_name=args.region)
        except Exception as e:
            print(f"Error initializing AWS clients: {str(e)}")
            exit(1)

        # Clear and initialize markdown file
        markdown_file = args.output
        with open(markdown_file, "w") as f:
            f.write(f"# AWS Port and Protocol Analysis\n\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Region: {args.region}\n")
            if args.profile:
                f.write(f"Profile: {args.profile}\n")
            f.write("\n")

        # Initialize list to store all port information
        all_ports = []

        # Get excluded services list
        excluded_services = set(service.lower() for service in (args.exclude_services or []))

        # Handle WAF-only mode
        if args.waf_only:
            try:
                list_waf_configs(clients['waf'], clients['wafregional'], clients['wafv2'], 
                               markdown_file, all_ports)
                list_alb_ports(clients['elbv2'], clients['waf'], markdown_file, all_ports)
            except Exception as e:
                print(f"Error in WAF-only analysis: {str(e)}")
            finally:
                list_all_ports(markdown_file, all_ports)
                write_security_recommendations(markdown_file, all_ports)
                print(f"WAF analysis completed. Documentation saved to {markdown_file}")
                return

        # Regular analysis mode
        service_mapping = {
            'sg': (list_security_group_rules, [clients['ec2']]),
            'alb': (list_alb_ports, [clients['elbv2'], clients['waf']]),
            'ecs': (list_ecs_ports, [clients['ecs']]),
            'rds': (list_rds_instances, [clients['rds']]),
            'waf': (list_waf_configs, [clients['waf'], clients['wafregional']]),
            'nacl': (list_nacl_rules, [clients['ec2']]),
            'nat': (list_nat_gateways, [clients['ec2']]),
            'vpc': (list_vpc_endpoints, [clients['ec2']])
        }

        # Process each service
        for service, (func, client_list) in service_mapping.items():
            if service not in excluded_services:
                try:
                    print(f"Analyzing {service.upper()}...")
                    func(*client_list, markdown_file, all_ports)
                except Exception as e:
                    print(f"Error analyzing {service}: {str(e)}")
                    write_to_markdown(markdown_file, f"\nError analyzing {service}: {str(e)}")

        # Generate consolidated view and recommendations
        try:
            list_all_ports(markdown_file, all_ports)
            write_security_recommendations(markdown_file, all_ports)
            
            # Add analysis timestamp at the end
            with open(markdown_file, "a") as f:
                f.write(f"\n\nAnalysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            print(f"Documentation successfully saved to {markdown_file}")

        except Exception as e:
            print(f"Error generating final analysis: {str(e)}")
            exit(1)

    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

def write_security_recommendations(markdown_file, all_ports):
    """Add security recommendations based on port analysis"""
    write_to_markdown(markdown_file, "\n# Security Recommendations")
    
    # Initialize counters and collections for analysis
    open_ports = set()
    high_risk_ports = {
        '22': 'SSH',
        '3389': 'RDP',
        '23': 'Telnet',
        '21': 'FTP',
        '20': 'FTP-DATA',
        '1433': 'MSSQL',
        '3306': 'MySQL'
    }
    
    recommendations = []
    
    # Analyze ports
    for _, _, port in all_ports:
        if port != 'N/A' and port != 'All':
            try:
                if '-' in str(port):
                    start, end = map(int, port.split('-'))
                    open_ports.update(range(start, end + 1))
                else:
                    open_ports.add(int(port))
            except ValueError:
                continue

    # Generate recommendations
    if any(int(port) in open_ports for port in high_risk_ports.keys()):
        risky_ports = [f"{port} ({high_risk_ports[str(port)]})" 
                      for port in high_risk_ports.keys() 
                      if int(port) in open_ports]
        recommendations.append(
            f"- High-risk ports detected: {', '.join(risky_ports)}. "
            "Consider restricting access to these ports to specific IP ranges."
        )

    if 'All' in {port for _, _, port in all_ports}:
        recommendations.append(
            "- Some resources allow all ports. Consider implementing more "
            "granular port access controls based on the principle of least privilege."
        )

    # Add general recommendations
    recommendations.extend([
        "- Regularly review and audit port configurations to ensure they align with business needs.",
        "- Consider using Security Groups as the primary means of access control rather than NACLs where possible.",
        "- Implement proper logging and monitoring for all open ports.",
        "- Use VPC endpoints for AWS services instead of public endpoints where possible.",
        "- Consider implementing AWS Network Firewall for additional network security controls."
    ])

    # Write recommendations
    for rec in recommendations:
        write_to_markdown(markdown_file, rec)

if __name__ == "__main__":
    main()