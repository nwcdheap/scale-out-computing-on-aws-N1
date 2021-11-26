import sys
import os
installer_path = "/".join(os.path.dirname(os.path.abspath(__file__)).split("/")[:-3])
sys.path.append(installer_path)
from prompt import get_input as get_input
import os

try:
    import boto3
    from colored import fg, bg, attr
    import ipaddress

except ImportError:
    print("boto3 extension is required. Run 'pip install boto3 ipaddress' and try again")
    sys.exit(1)


class FindExistingResource:
    def __init__(self, region, client_ip):
        self.region = region
        self.client_ip = client_ip
        session = boto3.Session(region_name=self.region)
        self.ec2 = session.client("ec2")
        self.efs = session.client("efs")
        self.fsx = session.client("fsx")
        self.ds = session.client("ds")
        self.install_parameters = {}
        self.main()

    def main(self):
        try:
            # List all VPCs
            vpc = self.find_vpc()
            if vpc["success"] is True:
                self.install_parameters["vpc_id"] = vpc["message"]["id"]
                self.install_parameters["vpc_cidr"] = vpc["message"]["cidr"]
            else:
                sys.exit(1)

            # List all Subnets
            public_subnets = self.get_subnets(self.install_parameters["vpc_id"], "public", [])
            if public_subnets["success"] is True:
                self.install_parameters["public_subnets"] = public_subnets["message"]
            else:
                print(f"{fg('red')}Error: {public_subnets['message']} {attr('reset')}")
                sys.exit(1)

            private_subnets = self.get_subnets(self.install_parameters["vpc_id"], "private", []) # public_subnets["message"] if you don't want to let customers re-use the same subnets
            if private_subnets["success"] is True:
                self.install_parameters["private_subnets"] = private_subnets["message"]
            else:
                print(f"{fg('red')}Error: {private_subnets['message']} {attr('reset')}")
                sys.exit(1)
            return self.install_parameters

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"{fg('red')}Unknown error: {exc_type} {fname} {exc_tb.tb_lineno} {attr('reset')}")
            sys.exit(1)

    def find_vpc(self):
        try:
            print(f"\n====== What {fg('misty_rose_3')}VPC{attr('reset')} in {self.region} do you want to use? ======\n")
            vpcs = {}
            count = 1
            for vpc in self.ec2.describe_vpcs()["Vpcs"]:
                resource_name = False
                if "Tags" in vpc.keys():
                    for tag in vpc["Tags"]:
                        if tag["Key"] == "Name":
                            resource_name = tag["Value"]

                vpcs[count] = {"id": vpc["VpcId"],
                               "description": f"{resource_name if resource_name is not False else ''} {vpc['VpcId']} {vpc['CidrBlock']}",
                               "cidr": vpc['CidrBlock']}
                count += 1
            [print("    {} > {}".format(key, value["description"])) for key, value in vpcs.items()]
            allowed_choices = list(vpcs.keys())
            choice = get_input(f"Choose the VPC you want to use?", None, allowed_choices, int)
            return {"success": True, "message": vpcs[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def find_directory_services(self):
        try:
            print(f"\n====== What {fg('misty_rose_3')}Directory Services (Microsoft AD){attr('reset')} in {self.region} do you want to use? ======\n")
            ds = {}
            count = 1
            for directory in self.ds.describe_directories()["DirectoryDescriptions"]:
                ds[count] = {"id": directory["DirectoryId"],
                             "name": directory["Name"],
                             "netbios": directory["ShortName"],
                             "dns": directory["DnsIpAddrs"],
                             "description": f"{directory['Name']} (Domain: {directory['ShortName']}, Id: {directory['DirectoryId']})"}
                count += 1
            [print("    {} > {}".format(key, value["description"])) for key, value in ds.items()]
            allowed_choices = list(ds.keys())
            choice = get_input(f"Choose the directory you want to use?", None, allowed_choices, int)
            return {"success": True, "message": ds[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_subnets(self, vpc_id, environment, selected_subnets=[]):
        try:
            if environment == "private":
                print(f"\n====== Select {fg('misty_rose_3')}3 subnets to use for your compute nodes (private subnets preferably) {attr('reset')} ======\n")
            else:
                print(f"\n====== Select {fg('misty_rose_3')}3 subnets to use for the main Scheduler and Load Balancer (public subnets preferably) {attr('reset')} ======\n")


            subnets = {}
            count = 1
            for subnet in self.ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']:
                resource_name = False
                if "Tags" in subnet.keys():
                    for tag in subnet["Tags"]:
                        if tag["Key"] == "Name":
                            resource_name = tag["Value"]

                if f"{subnet['SubnetId']},{subnet['AvailabilityZone']}" not in selected_subnets:
                    subnets[count] = {"id": subnet['SubnetId'],
                                      "availability_zone": subnet['AvailabilityZone'],
                                      "description": f"{resource_name if resource_name is not False else ''} {subnet['CidrBlock']} in {subnet['AvailabilityZone']}"}
                    count += 1

            [print("    {} > {}".format(key, value["description"])) for key, value in subnets.items()]
            selected_subnets = []
            while len(selected_subnets) != 3:
                allowed_choices = list(subnets.keys())
                if len(allowed_choices) == 0:
                    return {"success": False, "message": "Not enough subnets available"}
                choice = get_input(f"Choose your subnet #{len(selected_subnets) + 1} ?", None, allowed_choices, int)
                selected_subnets.append(f"{subnets[choice]['id']},{subnets[choice]['availability_zone']}")
                del subnets[choice]
            return {"success": True, "message": selected_subnets}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_fs(self, environment, selected_fs=[]):
        try:
            print(f"\n====== Choose what {fg('misty_rose_3')}EFS/FSx for Lustre{attr('reset')} you want to use for {environment} ======\n")
            filesystems = {}
            count = 1
            for filesystem in self.efs.describe_file_systems()["FileSystems"]:
                if filesystem["FileSystemId"] not in selected_fs:
                    filesystems[count] = {"id": f"{filesystem['FileSystemId']}",
                            "description": f"EFS: {filesystem['Name'] if 'Name' in filesystem.keys() else 'EFS: '} {filesystem['FileSystemId']}.efs.{self.region}.amazonaws.com"}
                    count += 1
            efs_count = count - 1
            for filesystem in self.fsx.describe_file_systems()["FileSystems"]:
                resource_name = False
                if filesystem["FileSystemId"] not in selected_fs:
                    for tag in filesystem['Tags']:
                        if tag["Key"] == 'Name':
                            resource_name = tag["Value"]
                    filesystems[count] = {"id": f"{filesystem['FileSystemId']}",
                            "description": f"FSX for Lustre: {resource_name if resource_name is not False else 'FSx for Lustre: '} {filesystem['FileSystemId']}.fsx.{self.region}.amazonaws.com"}
                    count += 1
            [print("    {} > {}".format(key, value["description"])) for key, value in filesystems.items()]
            allowed_choices = list(filesystems.keys())
            choice = get_input(f"Choose the filesystem to use for {environment}?", None, allowed_choices, int)
            if choice <= efs_count:
                return {"success": True, "message": filesystems[choice]["id"], "provider": "efs"}
            else:
                return {"success": True, "message": filesystems[choice]["id"], "provider": "fsx_lustre"}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_security_groups(self, vpc, environment, scheduler_sg=[]):
        try:
            print(f"\n====== Choose the {fg('misty_rose_3')}security group to use for {environment} {attr('reset')} ======\n")
            sgs = {}
            count = 1
            for sg in self.ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc]}])['SecurityGroups']:
                resource_name = False
                if "Tags" in sg.keys():
                    for tag in sg["Tags"]:
                        if tag["Key"] == "Name":
                            resource_name = tag["Value"]

                if sg['GroupId'] not in scheduler_sg:
                    sgs[count] = {"id": f"{sg['GroupId']}",
                                  "description": f"{resource_name if resource_name is not False else ''} {sg['GroupId']} {sg['GroupName']}"}

                    count += 1

            [print("    {} > {}".format(key, value["description"])) for key, value in sgs.items()]
            allowed_choices = list(sgs.keys())
            choice = get_input(f"What SG for you want to use for {environment}", None, allowed_choices, int)
            return {'success': True, 'message': sgs[choice]["id"]}

        except Exception as err:
            return {'success': False, 'message': str(err)}

    def get_rules_for_security_group(self, sg_ids):
        try:
            rules = {}
            for sg_id in sg_ids:
                for sg in self.ec2.describe_security_groups()['SecurityGroups']:
                    sg_rules = []
                    if sg['GroupId'] == sg_id:
                        if 'IpPermissions' in sg.keys():
                            for permission in sg['IpPermissions']:
                                if 'FromPort' in permission.keys():
                                    from_port = permission['FromPort']
                                    to_port = permission['ToPort']
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission['IpRanges'].__len__() > 0:
                                    for r in permission['IpRanges']:
                                        if 'CidrIp' in r.keys():
                                            approved_ips.append(r['CidrIp'])

                                if permission['UserIdGroupPairs'].__len__() > 0:
                                    for g in permission['UserIdGroupPairs']:
                                        if 'GroupId' in g.keys():
                                            approved_ips.append(g['GroupId'])

                                sg_rules.append({'from_port': from_port,
                                                        'to_port': to_port,
                                                        'approved_ips': approved_ips,
                                                        'type': 'ingress'})

                                rules[sg_id] = sg_rules

                        if 'IpPermissionsEgress' in sg.keys():
                            for permission in sg['IpPermissionsEgress']:
                                if 'FromPort' in permission.keys():
                                    from_port = permission['FromPort']
                                    to_port = permission['ToPort']
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission['IpRanges'].__len__() > 0:
                                    for r in permission['IpRanges']:
                                        if 'CidrIp' in r.keys():
                                            approved_ips.append(r['CidrIp'])

                                if permission['UserIdGroupPairs'].__len__() > 0:
                                    for g in permission['UserIdGroupPairs']:
                                        if 'GroupId' in g.keys():
                                            approved_ips.append(g['GroupId'])

                                sg_rules.append({'from_port': from_port,
                                                  'to_port': to_port,
                                                  'approved_ips': approved_ips,
                                                  'type': 'egress'})

                                rules[sg_id] = sg_rules

            return {'success': True,
                    'message': rules}

        except Exception as err:
            return {'success': False,
                    'message': str(err)}

    def get_fs_security_groups(self, cfn_params):
        import json
        try:
            filesystems = {}
            efs_ids=[]
            sgs = []

            if cfn_params["fs_apps_provider"] == "efs":
                efs_ids.append(cfn_params["fs_apps"])
            if cfn_params["fs_data_provider"] == "efs":
                efs_ids.append(cfn_params["fs_data"])
            for id in efs_ids:
                for mount in self.efs.describe_mount_targets(FileSystemId=id.split(".")[0])["MountTargets"]:
                    for sg in self.efs.describe_mount_target_security_groups(MountTargetId=mount["MountTargetId"])['SecurityGroups']:
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[id] = sgs

            fsx_ids=[]
            if cfn_params["fs_apps_provider"] == "fsx_lustre":
                fsx_ids.append(cfn_params["fs_apps"])
            if cfn_params["fs_data_provider"] == "fsx_lustre":
                fsx_ids.append(cfn_params["fs_data"])
            for id in fsx_ids:
                for network_interface in self.fsx.describe_file_systems(FileSystemIds=[id])["FileSystems"][0]["NetworkInterfaceIds"]:
                    for groups in self.ec2.describe_network_interface_attribute(Attribute='groupSet', NetworkInterfaceId=network_interface)["Groups"]:
                        sg = groups['GroupId']
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[id] = sgs
            return {"success": True, "message": filesystems}

        except Exception as err:
            return {'success': False, 'message': str(err)}

    def validate_sg_rules(self, cfn_params, check_fs=True):
        try:
            # Begin Verify Security Group Rules
            print(f"\n====== Please wait a little as we {fg('misty_rose_3')}validate your security group rules {attr('reset')} ======\n")
            sg_rules = self.get_rules_for_security_group([cfn_params["scheduler_sg"], cfn_params["compute_node_sg"]])
            if check_fs is True:
                fs_sg = self.get_fs_security_groups(cfn_params)

            if sg_rules["success"] is True:
                scheduler_sg_rules = sg_rules["message"][cfn_params["scheduler_sg"]]
                compute_node_sg_rules = sg_rules["message"][cfn_params["compute_node_sg"]]
            else:
                print(f"{fg('red')}Error: {sg_rules['message']} {attr('reset')}")
                sys.exit(1)

            errors = {}
            errors["SCHEDULER_SG_IN_COMPUTE"] = {
                    "status": False,
                    "error": f"Compute Node SG must allow all TCP traffic from Scheduler SG",
                    "resolution": f"Add new rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['scheduler_sg']}"}
            errors["COMPUTE_SG_IN_SCHEDULER"] = {
                    "status": False,
                    "error": f"Scheduler SG must allow all TCP traffic from Compute Node SG",
                    "resolution": f"Add a new rule on {cfn_params['scheduler_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}"}
            errors["CLIENT_IP_HTTPS_IN_SCHEDULER"] = {
                    "status": False,
                    "error": f"Client IP must be allowed for port 443 (80 optional) on Scheduler SG",
                    "resolution": f"Add two rules on {cfn_params['scheduler_sg']} that allow TCP ports 80 and 443 for {self.client_ip}"}
            errors["CLIENT_IP_SSH_IN_SCHEDULER"] = {
                    "status": False,
                    "error": f"Client IP must be allowed for port 22 (SSH) on Scheduler SG",
                    "resolution": f"Add one rule on {cfn_params['scheduler_sg']} that allow TCP port 22 for {self.client_ip}"}
            errors["SCHEDULER_SG_EQUAL_COMPUTE"] = {
                    "status": False,
                    "error": "Scheduler SG and Compute SG must be different",
                    "resolution": "You must choose two different security groups"}
            errors["COMPUTE_SG_EGRESS_EFA"] = {
                    "status": False,
                    "error": "Compute SG must reference egress traffic to itself for EFA",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}. Make sure you configure EGRESS rule and not INGRESS"}

            if check_fs is True:
                errors["FS_APP_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_apps']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Apps {cfn_params['fs_apps']}"}

                errors["FS_DATA_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_data']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Data {cfn_params['fs_data']}"}

            # Verify Scheduler Rules
            for rules in scheduler_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params['compute_node_sg'] in rule:
                            errors["COMPUTE_SG_IN_SCHEDULER"]["status"] = True

                if rules["from_port"] == 443 or rules["from_port"] == 22:
                    for rule in rules["approved_ips"]:
                        client_ip_netmask = 32
                        if client_ip_netmask == '32':
                            if ipaddress.IPv4Address(self.client_ip) in ipaddress.IPv4Network(rule):
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"]["status"] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"]["status"] = True
                        else:
                            if self.client_ip in rule:
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"]["status"] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"]["status"] = True
            # Verify Compute Node Rules
            for rules in compute_node_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params['scheduler_sg'] in rule:
                            errors["SCHEDULER_SG_IN_COMPUTE"]["status"] = True

                        if rules["type"] == "egress":
                            if cfn_params['compute_node_sg'] in rule:
                                errors["COMPUTE_SG_EGRESS_EFA"]["status"] = True

            if check_fs is True:
                if cfn_params['scheduler_sg'] in fs_sg["message"][cfn_params['fs_apps']] and cfn_params['compute_node_sg'] in fs_sg["message"][cfn_params['fs_apps']]:
                    errors["FS_APP_SG"]["status"] = True

                if cfn_params['scheduler_sg'] in fs_sg["message"][cfn_params['fs_data']] and cfn_params['compute_node_sg'] in fs_sg["message"][cfn_params['fs_data']]:
                    errors["FS_DATA_SG"]["status"] = True

            if cfn_params["scheduler_sg"] != cfn_params["compute_node_sg"]:
                errors["SCHEDULER_SG_EQUAL_COMPUTE"]["status"] = True

            sg_errors = {}

            confirm_sg_settings = False
            for error_id, error_info in errors.items():
                if error_info["status"] is False:
                    if check_fs is False and "EFS" in error_id:
                        pass
                    else:
                        print(f"{fg('yellow')}ATTENTION!! {error_info['error']} {attr('reset')}\nHow to solve: {error_info['resolution']}\n")
                        sg_errors[error_info["error"]] = error_info["resolution"]
                        confirm_sg_settings = True

            if confirm_sg_settings:
                choice = get_input("Your security groups may not be configured correctly. Verify them and determine if the warnings listed above are false-positive.\n Do you still want to continue with the installation?",
                                   None, ["yes", "no"], str)
                if choice.lower() == "no":
                    sys.exit(1)
            else:
                print(f"{fg('green')} Security Groups seems to be configured correctly{attr('reset')}")

            return {"success": True,
                    "message": ""}

        except Exception as e:

            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"{exc_type} {fname} {exc_tb.tb_lineno}")
            return {"success": False, "message": f"{exc_type} {fname} {exc_tb.tb_lineno}"}
