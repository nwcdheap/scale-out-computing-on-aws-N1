#!/usr/bin/env python3

"""
It's recommended to trigger this script via ./soca_installer.sh as python's virtual env and all required
libraries/dependencies will be automatically installed.

If you trigger ./install_soca.py directly, make sure to have all the Python and CDK dependencies installed
"""

try:
    import sys
    from colored import fg, bg, attr
    import boto3
    from requests import get
    from requests.exceptions import RequestException, Timeout
    from botocore.client import ClientError
    from botocore.exceptions import ProfileNotFound,ValidationError
    import shutil
    import urllib3
except ImportError:
    print(" > You must have 'colored', 'boto3' and 'requests' installed. Run 'pip install boto3 colored requests' first")
    sys.exit(1)
import time
import datetime
import os
import random
import string
import re
import argparse
from shutil import make_archive, copytree
installer_path = "/".join(os.path.dirname(os.path.abspath(__file__)).split("/")[:-3])
sys.path.append(installer_path)
from prompt import get_input as get_input
import find_existing_resources as find_existing_resources
urllib3.disable_warnings()


def detect_customer_ip():
    # Try to determine the IP of the customer.
    # If IP cannot be determined we will prompt the user to enter the value manually
    print("\n====== Trying to detect your IP. Use --client-ip to specify it manually instead ======\n")
    try:
        get_client_ip = get("https://ifconfig.co/json", timeout=15)
        if get_client_ip.status_code == 200:
            client_ip = f"{get_client_ip.json()['ip']}/32"
        else:
            print(f"Unable to automatically determine client IP: {get_client_ip}")
            client_ip = False
    except RequestException as e:
        print(f"Unable to automatically determine client IP: {e}")
        client_ip = False
    return client_ip


def accepted_aws_resources():
    # Retrieve all AWS resources. Currently only used to find all available SSH keypair
    accepted_values = {}
    try:
        accepted_values["accepted_keypairs"] = [key["KeyName"] for key in ec2.describe_key_pairs()["KeyPairs"]]
        if len(accepted_values) == 0:
            print(f"{fg('red')} No SSH keys found on this region. Please create one first{attr('reset')}")
            sys.exit(1)
    except ClientError as err:
        print(f"{fg('yellow')}Unable to list SSH keys, you will need to enter it manually or give ec2:Describe* IAM permission. {err} {attr('reset')}")
        accepted_values["accepted_keypairs"] = []

    return accepted_values


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create SOCA installer")
    parser.add_argument("--profile", "-p", type=str, help="AWS CLI profile to use. See https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html")
    parser.add_argument("--region", "-r", type=str, help="AWS region where you want to deploy your SOCA environment.")
    parser.add_argument("--bucket", "-b", type=str, help="S3 Bucket to use")
    parser.add_argument("--ldap-user", "-lu", type=str, help="Username of your first ldap user. This user has admin privileges")
    parser.add_argument("--ldap-password", "-lp", type=str, help="Password for your first ldap user")
    parser.add_argument("--ssh-keypair", "-ssh", type=str, help="SSH key to use")
    parser.add_argument("--custom-ami", "-ami", type=str, help="Specify a custom image")
    parser.add_argument("--ebs-snap", "-ebs", type=str, help="Apps EBS snap id")
    parser.add_argument("--vpc-cidr", "-cidr", type=str, help="What CIDR do you want to use your your VPC (eg: 10.0.0/16)")
    parser.add_argument("--client-ip", "-ip", type=str, help="Client IP authorized to access SOCA on port 22/443")
    parser.add_argument("--name", "-n", type=str, help="Friendly name for your SOCA cluster. Must be unique. SOCA will be added as prefix")
    parser.add_argument("--mode", "-m", type=int, choices=[1, 2], help="Choose default installation (1) or re-use some existing resources (2)")
    parser.add_argument("--operating-system", "-os", type=str, help="OS")
    parser.add_argument("--debug", action='store_const', const=True, default=False, help="Enable CDK debug mode")
    parser.add_argument("--cdk-cmd", type=str, choices=["deploy", "ls", "list", "synth", "synthesize", "destroy", "bootstrap"], default="deploy")
    args = parser.parse_args()
    # Use script location as current working directory
    install_directory = os.path.dirname(os.path.realpath(__file__))
    os.chdir(install_directory)

    print(f"""
            {fg('red')}_____{fg('light_blue')} ____  {fg('magenta')}______{fg('yellow')}___{attr('reset')} 
           {fg('red')}/ ___/{fg('light_blue')}/ __ \{fg('magenta')}/ ____{fg('yellow')}/   |{attr('reset')} 
           {fg('red')}\__ \{fg('light_blue')}/ / / {fg('magenta')}/ /   {fg('yellow')}/ /| |{attr('reset')} 
          {fg('red')}___/{fg('light_blue')} / /_/ {fg('magenta')}/ /___{fg('yellow')}/ ___ |{attr('reset')} 
         {fg('red')}/____/{fg('light_blue')}\____/{fg('magenta')}\____{fg('yellow')}/_/  |_|{attr('reset')}                     
        {fg('red')}Scale{attr('reset')}-{fg('light_blue')}Out{attr('reset')} {fg('magenta')}Computing{attr('reset')} on {fg('yellow')}AWS{attr('reset')}
    ================================
    源码: https://github.com/nwcd-samples/scale-out-computing-on-aws

====== 您想如何安装SOCA ? ======\n
    1 > 新建VPC
    2 > 使用现有VPC，请确认现有VPC有3个公有子网、3个私有子网，并且3个私有子网都有对应的NAT Gateway""")
    mode = get_input("请输入", args.mode, [1, 2], int)

    # Load AWS custom profile if specified
    if args.profile:
        try:
            session = boto3.session.Session(profile_name=args.profile)
        except ProfileNotFound:
            print(f"{fg('red')} Profile {args.profile} not found. Check ~/.aws/credentials file{attr('reset')}")
            sys.exit(1)
    else:
        session = boto3.session.Session()

    # Determine all AWS regions available on the account. We do not display opt-out region
    ec2 = boto3.client("ec2")
    try:
        accepted_regions = [region["RegionName"] for region in ec2.describe_regions()["Regions"]]
    except ClientError as err:
        print(
            f"{fg('yellow')}Unable to list all AWS regions, you will need to enter it manually or give ec2:Describe* IAM permission. {err} {attr('reset')}")
        accepted_regions = []

    # Choose region where to install SOCA
    region = get_input("您想把SOCA安装在哪个区域？", args.region, accepted_regions, str)
    china_region = True if region in ['cn-north-1', 'cn-northwest-1'] else False 

    # Initiate boto3 client now the region is known
    ec2 = session.client("ec2", region_name=region)
    sts = session.client("sts", region_name=region)
    s3 = session.resource("s3", region_name=region)
    cloudformation = session.client("cloudformation", region_name=region)
    iam = session.client("iam", region_name=region)
    accepted_aws_values = accepted_aws_resources()

    # Retrieve the AWS Account ID for CDK
    try:
        account_id = sts.get_caller_identity()["Account"]
    except Exception as err:
        print(f"{fg('red')} Unable to retrieve the Account ID due to {err}{attr('reset')}")
        sys.exit(1)

    # User Specified Variables
    if mode == 1:
        vpc_cidr = get_input("VPC的CIDR想使用什么？推荐10.0.0.0/16", args.vpc_cidr, None, str)
        cidr_regex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'
        while not re.match(cidr_regex, vpc_cidr):
            print(f"{fg('red')} 无效的CIDR {vpc_cidr}。格式必须是x.x.x.x/x (eg: 10.0.0.0/16){attr('reset')}")
            vpc_cidr = get_input("VPC的CIDR想使用什么？推荐10.0.0.0/16", None, None, str)
    else:
        # VPC will be specified by user when using mode=2
        vpc_cidr = None

    name = get_input("请输入集群名称，（“soca-”会自动作为前缀添加）", args.name, None, str)
    ldap_user = get_input("请输入LDAP第一个用户名，这个账号会赋予管理员权限", args.ldap_user, None, str)
    ldap_password = get_input("请输入LDAP第一个用户的密码", args.ldap_password, None, str)

    while not re.match("^(?:(?=.*[a-z])(?:(?=.*[A-Z])(?=.*[\d\W])|(?=.*\W)(?=.*\d))|(?=.*\W)(?=.*[A-Z])(?=.*\d)).{8,}$", ldap_password):
        print(f"{fg('red')}密码必须包含一个大写字母、一个小写字母，一个数字，最低8位。{attr('reset')}")
        ldap_password = get_input("请输入LDAP第一个用户的密码", None, None, str)

    base_os = get_input("请选择一个操作系统（计算节点运行时可以改变）", args.operating_system, ["amazonlinux2", "centos7", "rhel7"], str)
    ssh_keypair = get_input("请选择SSH key", args.ssh_keypair, accepted_aws_values["accepted_keypairs"], str)

    # Automatically detect client ip if needed
    if not args.client_ip:
        client_ip = detect_customer_ip()
        print(f"{fg('yellow')}We determined your IP is {client_ip}. You can change it later if you are running behind a proxy{attr('reset')}")
        if client_ip is False:
            client_ip = get_input("Client IP authorized to access SOCA on port 443/22", args.client_ip, None, str)
    else:
        client_ip = args.client_ip

    if client_ip.endswith("/32"):
        pass
    else:
        if "/" not in client_ip:
            print(f"{fg('yellow')}No subnet defined for your IP. Adding /32 at the end of {client_ip}{attr('reset')}")
            client_ip = f"{client_ip}/32"

    if args.custom_ami:
        custom_ami = args.custom_ami
    else:
        custom_ami = None

    if args.ebs_snap:
        ebs_snap = args.ebs_snap
    else:
        ebs_snap = None

    # All inputs received, preparing the CDK command
    vpc_azs = []
    public_subnets = []
    private_subnets = []
    if mode == 2:
        # Use existing resources running on customer's AWS account
        existing_resources = find_existing_resources.FindExistingResource(region=region, client_ip=client_ip).__dict__["install_parameters"]

        # Retrieve existing subnets and respective AZs
        for subnet in existing_resources["public_subnets"]:
            subnet_info = subnet.split(",")
            public_subnets.append(subnet_info[0])
            az = subnet_info[1]
            if az not in vpc_azs:
                vpc_azs.append(az)
        for subnet in existing_resources["private_subnets"]:
            subnet_info = subnet.split(",")
            private_subnets.append(subnet_info[0])
            az = subnet.split(",")[1]
            if az not in vpc_azs:
                vpc_azs.append(az)
    else:
        # Let SOCA create everything
        existing_resources = {}

    # Sanitize cluster name (remove any non alphanumerical character) or generate random cluster identifier
    if name:
        sanitized_cluster_id = re.sub(r"\W+", "-", name)
        sanitized_cluster_id = re.sub(r"soca-", "", sanitized_cluster_id)  # remove soca- if specified by the user
        cluster_id = f"soca-{sanitized_cluster_id.lower()}"
        if len(sanitized_cluster_id) > 15:
            print(f"{fg('red')} Error. {sanitized_cluster_id} is more than 15 chars. (soca- is automatically added as a prefix). Please pick something shorter.{attr('reset')}")
            sys.exit(1)
    else:
        unique_id = "".join(random.choice(string.ascii_lowercase) + random.choice(string.digits) for i in range(2))
        cluster_id = f"soca-{unique_id.lower()}"

    params = {"base_os": base_os,
              "account_id": account_id,
              "ldap_user": ldap_user,
              "ldap_password": ldap_password,
              "ssh_keypair": ssh_keypair,
              "cluster_name": name,
              "cluster_id": cluster_id,
              "custom_ami": custom_ami,
              "ebs_snap": ebs_snap,
              "region": region,
              "client_ip": client_ip,
              "vpc_cidr": vpc_cidr if mode == 1 else existing_resources["vpc_cidr"],
              "existing_vpc_azs": None if mode == 1 else ",".join(vpc_azs),  # CDK does not support passing array
              "existing_vpc_id": None if mode == 1 else existing_resources["vpc_id"],
              "existing_vpc_cidr": None if mode == 1 else existing_resources["vpc_cidr"],
              "existing_public_subnets": None if mode == 1 else ",".join(public_subnets),
              "existing_private_subnets": None if mode == 1 else ",".join(private_subnets)
              }

    # Prepare CDK commands
    cmd = f"cdk {args.cdk_cmd} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in params.items() if val is not None)} --require-approval never"
    cmd_boostrap = f"cdk bootstrap aws://{account_id}/{region} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in params.items() if val is not None)}"
    #cmd = "cdk "+args.cdk_cmd+" -c "+' -c '.join('{}=\"{}\"'.format(key, val) for (key, val) in params.items() if val is not None)+" --require-approval never"
    #cmd_boostrap = "cdk bootstrap aws://"+account_id+"/"+region+" -c "+' -c '.join('{}=\"{}\"'.format(key, val) for (key, val) in params.items() if val is not None)

    if args.debug:
        cmd += " --debug -v -v -v"

    if args.profile:
        cmd += f" --profile {args.profile}"
        cmd_boostrap += f" --profile {args.profile}"

    print(f"Executing {cmd}")

    # Log command in history book
    with open("installer_history.txt", "a+") as f:
        f.write(f"\n[{datetime.datetime.utcnow()}] {cmd_boostrap}")
        f.write(f"\n[{datetime.datetime.utcnow()}] {cmd}")

    # First, Bootstrap the environment. This will create a staging S3 bucket if needed
    print("\n====== Running CDK Boostrap ======\n")

    boostrap_environment = os.system(cmd_boostrap) # nosec
    if int(boostrap_environment) != 0:
        print(f"{fg('red')} Error! Unable to boostrap environment. Please run cdk bootstrap aws://{account_id}/{region} -c {' -c '.join('{}={}'.format(key,val) for (key,val) in params.items() if val is not None)}/ and fix any errors{attr('reset')}")
        sys.exit(1)

    # Then launch the actual SOCA installer
    print("\n====== Deploying SOCA ======\n")

    launch_installer = os.system(cmd) # nosec
    if args.cdk_cmd == "deploy":
        if int(launch_installer) == 0:
            # SOCA is installed. We will know wait until SOCA is fully configured (when the ELB returns HTTP 200)
            print(f"{fg('green')}SOCA was installed successfully!{attr('reset')}")
            try:
                check_cfn = cloudformation.describe_stacks(StackName=cluster_id)
                for output in check_cfn["Stacks"][0]["Outputs"]:
                    if output["OutputKey"] == "WebUserInterface":
                        print(f"SOCA Web Endpoint is {output['OutputValue']}. Now checking if SOCA is fully configured (this could take up to 20 minutes)")
                        soca_check_loop = 0
                        # Run a first check to determine if client IP provided by the customer is valid
                        try:
                            check_firewall = get(f"{output['OutputValue']}", verify=False, timeout=35) # nosec
                        except Timeout:
                            print(f"{fg('yellow')}Unable to connect to the SOCA endpoint URL. Maybe your IP {client_ip} is not valid/has changed (maybe you are behind a proxy?). If that's the case please go to AWS console and authorize your real IP on the Scheduler Security Group{attr('reset')}")
                            sys.exit(1)

                        while get(output['OutputValue'], verify=False, timeout=15).status_code != 200 or soca_check_loop > 10: # nosec
                            print("SOCA not ready yet, checking again in 120 seconds ... ")
                            time.sleep(120)
                            soca_check_loop += 1

                        print(f"{fg('green')}SOCA is ready! Login via  {output['OutputValue']}{attr('reset')}")

            except ValidationError:
                print(f"{cluster_id} is not a valid cloudformation stack")
            except ClientError as err:
                print(f"Unable to retrieve {cluster_id} stack outputs, probably due to a permission error (your IAM account do not have permission to run cloudformation:Describe*. Log in to AWS console to view your stack connection endpoints")

    elif args.cdk_cmd == "destroy":
        # Destroy stack if known
        cmd_destroy = f"cdk destroy {cluster_id} -c {' -c '.join('{}={}'.format(key, val) for (key, val) in params.items() if val is not None)} --require-approval never"
        print(f"Deleting stack, running {cmd_destroy}")
        delete_stack = os.system(cmd_destroy) # nosec
    else:
        # synth, ls etc ..
        pass
