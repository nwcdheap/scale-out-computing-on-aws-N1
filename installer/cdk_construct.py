#!/usr/bin/env python3

from aws_cdk import core
import os
import datetime
from aws_cdk import (
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_events as events,
    aws_lambda as aws_lambda,
    aws_logs as logs,
    aws_iam as iam,
    aws_backup as backup,
    aws_secretsmanager as secretsmanager,
    aws_dynamodb,
    core as cdk)
import json
import sys
import yaml
from yaml.scanner import ScannerError
import random
import string
from types import SimpleNamespace


def get_install_properties():
    config_file_path = f"{os.path.dirname(os.path.realpath(__file__))}/config.yml"
    try:
        config_parameters = yaml.load(open(config_file_path, 'r'), Loader=yaml.FullLoader) # nosec
    except ScannerError as err:
        print(f"{config_file_path} is not a valid YAML file. Verify syntax, {err}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{config_file_path} not found")
        sys.exit(1)
    if config_parameters:
        return config_parameters
    else:
        sys.exit("No parameters were specified.")


class SOCAInstall(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Init SOCA resources
        self.soca_resources = {
            "acm_certificate_lambda_role": None,
            "alb": None,
            "backup_role": None,
            "compute_node_instance_profile": None,
            "compute_node_role": None,
            "compute_node_sg": None,
            "directory_service": None,
            "ami_id": user_specified_variables.custom_ami if user_specified_variables.custom_ami else install_props.RegionMap.__dict__[user_specified_variables.region].__dict__[user_specified_variables.base_os],
            "ebs_snap": user_specified_variables.ebs_snap if user_specified_variables.ebs_snap else install_props.Config.scheduler.apps_map.__dict__[user_specified_variables.region],
            "nat_gateway_ips": [],
            "reset_ds_password_lambda_role": None,
            "scheduler_eip": None,
            "scheduler_instance": None,
            "scheduler_role": None,
            "scheduler_sg": None,
            "spot_fleet_role": None,
            "soca_config": None,
            "vpc": None}

        # Create SOCA environment
        self.network()  # Create Network environment
        self.security_groups()  # Create Security Groups
        self.iam_roles()  # Create IAM roles and policies for primary roles needed to deploy resources
        self.scheduler()  # Configure the Scheduler
        self.viewer()  # Configure the DCV Load Balancer
        self.secretsmanager()  # Store SOCA config on Secret Manager
        self.db() # Store DCV events
        self.backups()  # Configure AWS Backup & Restore


    def network(self):
        """
        Create a VPC with 3 public and 3 private subnets.
        To save IP space, public subnets have a smaller range compared to private subnets (where we deploy compute node)

        Example: vpc_cidr: 10.0.0.0/17 --> vpc_cidr_prefix_bits = 17
        public_subnet_mask_prefix_bits = 4
        private_subnet_mask_prefix_bits = 2
        public_subnet_mask = 17 + 4 = 21
        Added condition to reduce size of public_subnet_mask to a maximum of /26
        private_SubnetMask = 17 + 2 = 19
        """
        if not user_specified_variables.existing_vpc_id:
            vpc_cidr_prefix_bits = user_specified_variables.vpc_cidr.split("/")[1]
            public_subnet_mask_prefix_bits = 4
            private_subnet_mask_prefix_bits = 2
            public_subnet_mask = int(vpc_cidr_prefix_bits) + int(public_subnet_mask_prefix_bits)
            if public_subnet_mask < 26:
                public_subnet_mask = 26
            private_subnet_mask = int(vpc_cidr_prefix_bits) + int(private_subnet_mask_prefix_bits)

            self.soca_resources["vpc"] = ec2.Vpc(self, "SOCAVpc", cidr=user_specified_variables.vpc_cidr,
                                                 nat_gateways=int(install_props.Config.network.nat_gateways),
                                                 enable_dns_support=True,
                                                 enable_dns_hostnames=True,
                                                 max_azs=int(install_props.Config.network.max_azs),
                                                 subnet_configuration=[ec2.SubnetConfiguration(cidr_mask=public_subnet_mask, name="Public", subnet_type=ec2.SubnetType.PUBLIC),
                                                                       ec2.SubnetConfiguration(cidr_mask=private_subnet_mask, name="Private", subnet_type=ec2.SubnetType.PRIVATE)])
            core.Tags.of(self.soca_resources["vpc"]).add("Name", f"{user_specified_variables.cluster_id}-VPC")
        else:
            # Use existing VPC. Existing VPCs must have 3 public and 3 private subnets
            public_subnet_ids = user_specified_variables.existing_public_subnets.split(",")
            private_subnet_ids = user_specified_variables.existing_private_subnets.split(",")
            self.soca_resources["vpc"] = ec2.Vpc.from_vpc_attributes(self, user_specified_variables.cluster_id,
                                                                     vpc_cidr_block=user_specified_variables.existing_vpc_cidr,
                                                                     availability_zones=user_specified_variables.existing_vpc_azs.split(","),
                                                                     vpc_id=user_specified_variables.existing_vpc_id,
                                                                     public_subnet_ids=public_subnet_ids,
                                                                     private_subnet_ids=private_subnet_ids)

        # Retrieve all NAT Gateways associated to the public subnets.
        for subnet_info in self.soca_resources["vpc"].public_subnets:
            nat_eip_for_subnet = subnet_info.node.try_find_child("EIP")
            if nat_eip_for_subnet:
                self.soca_resources["nat_gateway_ips"].append(nat_eip_for_subnet)

        # Create the EIP associated that will be associated to the scheduler
        if install_props.Config.entry_points_subnets.lower() == "public":
            self.soca_resources["scheduler_eip"] = ec2.CfnEIP(self, "SchedulerEIP", instance_id=None)
            core.Tags.of(self.soca_resources["scheduler_eip"]).add("Name",f"{user_specified_variables.cluster_id}-Scheduler")

    def security_groups(self):
        """
        Create two security groups (or re-use existing ones), one for the compute nodes and one for the scheduler
        """

        self.soca_resources["compute_node_sg"] = ec2.SecurityGroup(self, "ComputeNodeSG", vpc=self.soca_resources["vpc"], allow_all_outbound=False, description="Security Group used for all compute nodes")
        # We do not use `security_group_name` as it's not recommended in case you plan to do UPDATE_TEMPLATE in the future
        # Instead we simply assign a Name tag
        core.Tags.of(self.soca_resources["compute_node_sg"]).add("Name", f"{user_specified_variables.cluster_id}-ComputeNodeSG")

        self.soca_resources["scheduler_sg"] = ec2.SecurityGroup(self, "SchedulerSG", vpc=self.soca_resources["vpc"], allow_all_outbound=False, description="Security Group used for the scheduler host and ELB")
        # We do not use `security_group_name` as it's not recommended in case you plan to do UPDATE_TEMPLATE in the future
        # Instead we simply assign a Name tag
        core.Tags.of(self.soca_resources["scheduler_sg"]).add("Name", f"{user_specified_variables.cluster_id}-SchedulerSG")

        # Add rules. Ignore if already exist (in case you re-use existing SGs)
        self.soca_resources["compute_node_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.tcp_range(0, 65535), description="Allow all TCP traffic from VPC to compute")
        self.soca_resources["compute_node_sg"].add_ingress_rule(self.soca_resources["scheduler_sg"], ec2.Port.tcp_range(0, 65535), description="Allow all traffic from scheduler host to compute")
        self.soca_resources["compute_node_sg"].add_ingress_rule(self.soca_resources["compute_node_sg"], ec2.Port.all_traffic(), description="Allow all Ingress traffic between compute nodes and EFA")
        self.soca_resources["compute_node_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp_range(0, 65535), description="Allow all Egress TCP traffic for ComputeNode SG")
        self.soca_resources["compute_node_sg"].add_egress_rule(self.soca_resources["compute_node_sg"], ec2.Port.all_traffic(), description="Allow all Egress traffic for EFA")
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.tcp_range(0, 65535), description="Allow all TCP traffic from VPC to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(user_specified_variables.client_ip), ec2.Port.all_traffic(), description="Allow all Ingress traffic from customer IP to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(self.soca_resources["compute_node_sg"], ec2.Port.tcp_range(0, 65535), description="Allow all traffic from compute nodes to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(self.soca_resources["scheduler_sg"], ec2.Port.tcp(8443), description="Allow ELB healthcheck to communicate with the UI")
        self.soca_resources["scheduler_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp_range(0, 65535), description="Allow all Egress TCP traffic for Scheduler SG")

        if install_props.Config.entry_points_subnets.lower() == "public":
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(f"{self.soca_resources['scheduler_eip'].ref}/32"), ec2.Port.tcp(443), description=f"Allow HTTPS traffic from Scheduler to ELB to validate DCV sessions")

        for nat_eip in self.soca_resources["nat_gateway_ips"]:
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(f"{nat_eip.ref}/32"), ec2.Port.tcp(443), description=f"Allow NAT EIP to communicate to ELB/Scheduler")

        # Special rules are needed when using AWS Directory Services
        if install_props.Config.directoryservice.provider == "activedirectory":
            self.soca_resources["compute_node_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.udp_range(0, 1024), description="Allow all UDP traffic from VPC to compute. Required for Directory Service")
            self.soca_resources["compute_node_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.udp_range(0, 1024), description="Allow all Egress UDP traffic for ComputeNode SG. Required for Directory Service")
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.udp_range(0, 1024), description="Allow all UDP traffic from VPC to scheduler. Required for Directory Service")
            self.soca_resources["scheduler_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.udp_range(0, 1024), description="Allow all Egress UDP traffic for Scheduler SG. Required for Directory Service")

    def iam_roles(self):
        """
        Configure IAM roles & policies for the various resources
        """
        # Create IAM roles
        self.soca_resources["spot_fleet_role"] = iam.Role(self, 'SpotFleetRole', description="IAM role to manage SpotFleet requests", assumed_by=iam.ServicePrincipal(principals_suffix["spotfleet"]))
        self.soca_resources["backup_role"] = iam.Role(self, 'BackupRole', description="IAM role to manage AWS Backup & Restore jobs", assumed_by=iam.ServicePrincipal(principals_suffix["backup"]))
        self.soca_resources["scheduler_role"] = iam.Role(self, 'SchedulerRole', description="IAM role assigned to the scheduler host", assumed_by=iam.CompositePrincipal(iam.ServicePrincipal(principals_suffix["ssm"]), iam.ServicePrincipal(principals_suffix["ec2"])))
        self.soca_resources["compute_node_role"] = iam.Role(self, 'ComputeNodeRole', description="IAM role assigned to the compute nodes", assumed_by=iam.CompositePrincipal(iam.ServicePrincipal(principals_suffix["ssm"]), iam.ServicePrincipal(principals_suffix["ec2"])))
        self.soca_resources["acm_certificate_lambda_role"] = iam.Role(self, 'ACMCertificateLambdaRole', description="IAM role assigned to the ACMCertificate Lambda function", assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))

        # Add SSM Managed Policy
        self.soca_resources["scheduler_role"].add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        self.soca_resources["compute_node_role"].add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # Generate IAM inline policies
        self.soca_resources["compute_node_instance_profile"] = iam.CfnInstanceProfile(self, "ComputeNodeInstanceProfile", roles=[self.soca_resources["compute_node_role"].role_name])
        policy_substitutes = {"%%AWS_ACCOUNT_ID%%": core.Aws.ACCOUNT_ID,
                              "%%AWS_PARTITION%%": core.Aws.PARTITION,
                              "%%AWS_URL_SUFFIX%%": core.Aws.URL_SUFFIX,
                              "%%AWS_REGION%%": core.Aws.REGION,
                              "%%BUCKET%%": user_specified_variables.bucket,
                              "%%COMPUTE_NODE_ROLE_ARN%%": self.soca_resources["compute_node_role"].role_arn,
                              "%%SCHEDULER_ROLE_ARN%%": self.soca_resources["scheduler_role"].role_arn,
                              "%%SPOTFLEET_ROLE_ARN%%": self.soca_resources["spot_fleet_role"].role_arn,
                              "%%VPC_ID%%": self.soca_resources["vpc"].vpc_id,
                              "%%CLUSTER_ID%%": user_specified_variables.cluster_id}

        policy_templates = {"SpotFleetPolicy": {"template": "policies/SpotFleet.json", "attach_to_role": "spot_fleet_role"},
                            "ComputeNodePolicy": {"template": "policies/ComputeNode.json", "attach_to_role": "compute_node_role"},
                            "SchedulerPolicy": {"template": "policies/Scheduler.json", "attach_to_role": "scheduler_role"},
                            "ACMCertificateLambdaPolicy": {"template": "policies/ACMCertificateLambda.json", "attach_to_role": "acm_certificate_lambda_role"},
                            "BackupPolicy": {"template": "policies/Backup.json", "attach_to_role": "backup_role"}}

        # Create all policies and attach them to their respective role
        for policy_name, policy_data in policy_templates.items():
            with open(policy_data["template"]) as json_file:
                policy_content = json_file.read()

            for k, v in policy_substitutes.items():
                policy_content = policy_content.replace(k, v)

            self.soca_resources[policy_data["attach_to_role"]].attach_inline_policy(iam.Policy(self, f"{user_specified_variables.cluster_id}-{policy_name}", document=iam.PolicyDocument.from_json(json.loads(policy_content))))

    def scheduler(self):
        """
        Create the Scheduler EC2 instance, configure user data and assign EIP
        """

        # Generate EC2 User Data
        user_data_substitutes = {"%%AWS_ACCOUNT_ID%%": core.Aws.ACCOUNT_ID,
                                 "%%AWS_PARTITION%%": core.Aws.PARTITION,
                                 "%%CLUSTER_ID%%": user_specified_variables.cluster_id,
                                 "%%S3_BUCKET%%": user_specified_variables.bucket,
                                 "%%S3_BUCKET_FOLDER%%": install_props.Config.bucket_folder,
                                 "%%AWS_REGION%%": core.Aws.REGION,
                                 "%%COMPUTE_NODE_ARN%%": self.soca_resources["compute_node_role"].role_arn,
                                 "%%VPC_ID%%": self.soca_resources["vpc"].vpc_id,
                                 "%%BASE_OS%%": user_specified_variables.base_os,
                                 "%%LDAP_USERNAME%%": user_specified_variables.ldap_user,
                                 "%%LDAP_PASSWORD%%": user_specified_variables.ldap_password,
                                 "%%SOCA_INSTALL_AMI%%": self.soca_resources["ami_id"],
                                 "%%PIP_CHINA_MIRROR%%": install_props.Config.china.pip_china_mirror,
                                 "%%CENTOS_CHINA_REPO%%": install_props.Config.china.centos_china_repo,
                                 "%%SOCA_AUTH_PROVIDER%%": install_props.Config.directoryservice.provider,
                                 "%%SOCA_LDAP_BASE%%": "false" if install_props.Config.directoryservice.provider == "activedirectory" else f"dc={',dc='.join(install_props.Config.directoryservice.openldap.name.split('.'))}".lower()}

        with open("user_data/Scheduler.sh") as plain_user_data:
            user_data = plain_user_data.read()

        for k, v in user_data_substitutes.items():
            user_data = user_data.replace(k, v)

        # Choose subnet where to deploy the scheduler
        if not user_specified_variables.existing_vpc_id:
            if install_props.Config.entry_points_subnets.lower() == "public":
                vpc_subnets = ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].public_subnets[0]])
            else:
                vpc_subnets = ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].private_subnets[0]])
        else:
            if install_props.Config.entry_points_subnets.lower() == "public":
                existing_subnet_info = user_specified_variables.existing_public_subnets.split(",")
            else:
                existing_subnet_info = user_specified_variables.existing_private_subnets.split(",")
            launch_subnet = ec2.Subnet.from_subnet_attributes(self, "SubnetToUse",
                                                              availability_zone=user_specified_variables.existing_vpc_azs.split(",")[0],
                                                              subnet_id=existing_subnet_info[0])
            vpc_subnets = ec2.SubnetSelection(subnets=[launch_subnet])

        # Create the Scheduler Instance
        self.soca_resources["scheduler_instance"] = ec2.Instance(self, "SchedulerInstance",
                                                                 availability_zone=vpc_subnets.availability_zones,
                                                                 machine_image=ec2.MachineImage.generic_linux({
                                                                       user_specified_variables.region: self.soca_resources["ami_id"]}),
                                                                 instance_type=ec2.InstanceType("m5.large"),
                                                                 key_name=user_specified_variables.ssh_keypair,
                                                                 vpc=self.soca_resources["vpc"],
                                                                 block_devices=[ec2.BlockDevice(
                                                                       device_name="/dev/xvda" if user_specified_variables.base_os == "amazonlinux2" else "/dev/sda1",
                                                                       volume=ec2.BlockDeviceVolume(
                                                                           ebs_device=ec2.EbsDeviceProps(
                                                                               volume_size=int(install_props.Config.scheduler.volume_size),
                                                                               volume_type=ec2.EbsDeviceVolumeType.GP3))
                                                                        ),
                                                                     ec2.BlockDevice(
                                                                         device_name="/dev/sdb",
                                                                         volume=ec2.BlockDeviceVolume(
                                                                             ebs_device=ec2.EbsDeviceProps(
                                                                                 snapshot_id=self.soca_resources["ebs_snap"],
                                                                                 volume_size=int(
                                                                                     install_props.Config.scheduler.volume_size_apps),
                                                                                 volume_type=ec2.EbsDeviceVolumeType.GP3))
                                                                     )
                                                                 ],
                                                                 role=self.soca_resources["scheduler_role"],
                                                                 security_group=self.soca_resources["scheduler_sg"],
                                                                 vpc_subnets=vpc_subnets,
                                                                 user_data=ec2.UserData.custom(user_data))

        core.Tags.of(self.soca_resources["scheduler_instance"]).add("Name", f"{user_specified_variables.cluster_id}-Scheduler")
        core.Tags.of(self.soca_resources["scheduler_instance"]).add("soca:BackupPlan", user_specified_variables.cluster_id)

        ssh_user = "ec2-user"

        if install_props.Config.entry_points_subnets.lower() == "public":
            # Associate the EIP to the scheduler instance
            ec2.CfnEIPAssociation(self, "AssignEIPToScheduler",
                                  eip=self.soca_resources["scheduler_eip"].ref,
                                  instance_id=self.soca_resources["scheduler_instance"].instance_id)
            core.CfnOutput(self, "SchedulerIP", value=self.soca_resources["scheduler_eip"].ref)
            core.CfnOutput(self, "ConnectionString", value=f"ssh -i {user_specified_variables.ssh_keypair} {ssh_user}@{self.soca_resources['scheduler_eip'].ref}")

        else:
            core.CfnOutput(self, "SchedulerIP", value=self.soca_resources["scheduler_instance"].instance_private_ip)
            core.CfnOutput(self, "ConnectionString", value=f"ssh -i {user_specified_variables.ssh_keypair} {ssh_user}@{self.soca_resources['scheduler_instance'].instance_private_ip}")

    def secretsmanager(self):
        """
        Store SOCA configuration in a Secret Manager's Secret.
        Scheduler/Compute Nodes have the permission to read the secret
        """
        public_subnets = []
        private_subnets = []
        for pub_sub in self.soca_resources["vpc"].public_subnets:
            public_subnets.append(pub_sub.subnet_id)

        for priv_sub in self.soca_resources["vpc"].private_subnets:
            private_subnets.append(priv_sub.subnet_id)

        secret = {"VpcId": self.soca_resources["vpc"].vpc_id,
                  "PublicSubnet1": public_subnets[0],
                  "PublicSubnet2": public_subnets[1],
                  "PublicSubnet3": public_subnets[2],
                  "PrivateSubnet1": private_subnets[0],
                  "PrivateSubnet2": private_subnets[1],
                  "PrivateSubnet3": private_subnets[2],
                  "SchedulerPrivateIP": self.soca_resources["scheduler_instance"].instance_private_ip,
                  "SchedulerPrivateDnsName": self.soca_resources["scheduler_instance"].instance_private_dns_name,
                  "SchedulerInstanceId": self.soca_resources["scheduler_instance"].instance_id,
                  "SchedulerSecurityGroup": self.soca_resources["scheduler_sg"].security_group_id,
                  "ComputeNodeSecurityGroup": self.soca_resources["compute_node_sg"].security_group_id,
                  "SchedulerIAMRoleArn": self.soca_resources["scheduler_role"].role_arn,
                  "SpotFleetIAMRoleArn": self.soca_resources["spot_fleet_role"].role_arn,
                  "SchedulerIAMRole": self.soca_resources["scheduler_role"].role_name,
                  "ComputeNodeIAMRoleArn": self.soca_resources["compute_node_role"].role_arn,
                  "ComputeNodeIAMRole": self.soca_resources["compute_node_role"].role_name,
                  "ComputeNodeInstanceProfileArn": f"arn:{core.Aws.PARTITION}:iam::{core.Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['compute_node_instance_profile'].ref}",
                  "EFSDataDns": self.soca_resources["scheduler_instance"].instance_private_ip,
                  "EFSAppsDns": self.soca_resources["scheduler_instance"].instance_private_ip,
                  "ClusterId": user_specified_variables.cluster_id,
                  "Version": install_props.Config.version,
                  "S3Bucket": user_specified_variables.bucket,
                  "SSHKeyPair": user_specified_variables.ssh_keypair,
                  "CustomAMI": self.soca_resources["ami_id"],
                  "LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
                  "LoadBalancerArn": self.soca_resources["alb"].load_balancer_arn,
                  "BaseOS": user_specified_variables.base_os,
                  "S3InstallFolder": install_props.Config.bucket_folder,
                  "SchedulerPublicIP": self.soca_resources["scheduler_eip"].ref if install_props.Config.entry_points_subnets.lower() == "public" else self.soca_resources["scheduler_instance"].instance_private_ip,
                  "DefaultMetricCollection": "true",
                  "AuthProvider": install_props.Config.directoryservice.provider
                  }

        # LDAP configuration
        # OpenLDAP
        secret["LdapName"] = install_props.Config.directoryservice.openldap.name
        secret["LdapBase"] = f"dc={',dc='.join(secret['LdapName'].split('.'))}".lower()
        secret["LdapHost"] = self.soca_resources["scheduler_instance"].instance_private_dns_name

        self.soca_resources["soca_config"] = secretsmanager.CfnSecret(self, "SOCASecretManagerSecret",
                                                                      description=f"Store SOCA configuration for cluster {user_specified_variables.cluster_id}",
                                                                      kms_key_id=None if install_props.Config.secretsmanager.kms_key_id is False else install_props.Config.secretsmanager.kms_key_id,
                                                                      name=user_specified_variables.cluster_id,
                                                                      secret_string=json.dumps(secret))

        # Create IAM policy and attach it to both Scheduler and Compute Nodes group
        secret_manager_statement = iam.PolicyStatement(actions=["secretsmanager:GetSecretValue"], effect=iam.Effect.ALLOW, resources=[self.soca_resources["soca_config"].ref])
        self.soca_resources["scheduler_role"].attach_inline_policy(iam.Policy(self, "AttachSecretManagerPolicyToScheduler", statements=[secret_manager_statement]))
        self.soca_resources["compute_node_role"].attach_inline_policy(iam.Policy(self, "AttachSecretManagerPolicyToComputeNode", statements=[secret_manager_statement]))

    def db(self):
        aws_dynamodb.Table(
            self, "ddb"+user_specified_variables.cluster_id, table_name=user_specified_variables.cluster_id,
            partition_key=aws_dynamodb.Attribute(
                name="user",
                type=aws_dynamodb.AttributeType.STRING
            ),
            sort_key=aws_dynamodb.Attribute(
                name="gmt_create",
                type=aws_dynamodb.AttributeType.STRING
            ),
            billing_mode=aws_dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=core.RemovalPolicy.DESTROY,
        )


    def backups(self):
        """
        Deploy AWS Backup vault. Scheduler EC2 instance and both EFS will be backup on a daily basis
        """
        vault = backup.BackupVault(self, "SOCABackupVault",
                                   backup_vault_name=f"{user_specified_variables.cluster_id}-BackupVault",
                                   removal_policy=core.RemovalPolicy.DESTROY)  # removal policy won't apply if backup vault is not empty
        plan = backup.BackupPlan(self, "SOCABackupPlan",
                                 backup_plan_name=f"{user_specified_variables.cluster_id}-BackupPlan",
                                 backup_plan_rules=[backup.BackupPlanRule(backup_vault=vault,
                                                                          start_window=core.Duration.minutes(60),
                                                                          delete_after=core.Duration.days(int(install_props.Config.backups.delete_after)),
                                                                          schedule_expression=events.Schedule.expression("cron(0 5 * * ? *)"))])
        # Backup EFS/EC2 resources with special tag: soca:BackupPlan, value: Current Cluster ID
        backup.BackupSelection(self, "SOCABackupSelection", backup_plan=plan, role=self.soca_resources["backup_role"],
                               backup_selection_name=f"{user_specified_variables.cluster_id}-BackupSelection",
                               resources=[backup.BackupResource(tag_condition=backup.TagCondition(key="soca:BackupPlan",
                                                                                                  value=user_specified_variables.cluster_id,
                                                                                                  operation=backup.TagOperation.STRING_EQUALS))])

    def viewer(self):
        # Create the ALB. It's used to forward HTTP/S traffic to DCV hosts, Web UI
        self.soca_resources["alb"] = elbv2.ApplicationLoadBalancer(self, f"{user_specified_variables.cluster_id}-ELBv2Viewer",
                                                                   load_balancer_name=f"{user_specified_variables.cluster_id}-viewer",
                                                                   security_group=self.soca_resources["scheduler_sg"],
                                                                   http2_enabled=True,
                                                                   vpc=self.soca_resources["vpc"],
                                                                   internet_facing=True if install_props.Config.entry_points_subnets.lower() == "public" else False)
        # HTTP listener simply forward to HTTPS
        self.soca_resources["alb"].add_listener("HTTPListener", port=80, open=False, protocol=elbv2.ApplicationProtocol.HTTP,
                                                default_action=elbv2.ListenerAction(
                                                    action_json=elbv2.CfnListener.ActionProperty(
                                                        type="redirect",
                                                        redirect_config=elbv2.CfnListener.RedirectConfigProperty(
                                                            host="#{host}",
                                                            path="/#{path}",
                                                            port="443",
                                                            protocol="HTTPS",
                                                            query="#{query}",
                                                            status_code="HTTP_301"))))

        # Create self-signed certificate (if needed) for HTTPS listener (via AWS Lambda)
        create_acm_certificate_lambda = aws_lambda.Function(self, f"{user_specified_variables.cluster_id}-ACMCertificateLambda",
                                                            function_name=f"{user_specified_variables.cluster_id}-CreateACMCertificate",
                                                            description="Create first self-signed certificate for ALB",
                                                            memory_size=128, role=self.soca_resources["acm_certificate_lambda_role"],
                                                            runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                            timeout=core.Duration.minutes(1),
                                                            log_retention=logs.RetentionDays.INFINITE,
                                                            handler="CreateELBSSLCertificate.generate_cert",
                                                            code=aws_lambda.Code.asset("functions/CreateELBSSLCertificate"))

        cert_custom_resource = core.CustomResource(self, "RetrieveACMCertificate",
                                                   service_token=create_acm_certificate_lambda.function_arn,
                                                   properties={"LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
                                                               "ClusterId": user_specified_variables.cluster_id})

        cert_custom_resource.node.add_dependency(create_acm_certificate_lambda)
        cert_custom_resource.node.add_dependency(self.soca_resources["acm_certificate_lambda_role"])

        soca_webui_target_group = elbv2.CfnTargetGroup(self, f"{user_specified_variables.cluster_id}-SOCAWebUITargetGroup", port=8443, protocol="HTTPS", target_type="instance", vpc_id=self.soca_resources["vpc"].vpc_id,
                                                       name=f"{user_specified_variables.cluster_id}-WebUI",
                                                       targets=[elbv2.CfnTargetGroup.TargetDescriptionProperty(id=self.soca_resources["scheduler_instance"].instance_id)],
                                                       health_check_path="/ping")

        https_listener = elbv2.CfnListener(self, "HTTPSListener", port=443, ssl_policy="ELBSecurityPolicy-2016-08",
                                           load_balancer_arn=self.soca_resources["alb"].load_balancer_arn, protocol="HTTPS",
                                           certificates=[elbv2.CfnListener.CertificateProperty(certificate_arn=cert_custom_resource.get_att_string('ACMCertificateArn'))],
                                           default_actions=[elbv2.CfnListener.ActionProperty(
                                               type="forward", target_group_arn=soca_webui_target_group.ref)])
        https_listener.node.add_dependency(cert_custom_resource)

        core.CfnOutput(self, "web", value="https://"+self.soca_resources["alb"].load_balancer_dns_name)


if __name__ == "__main__":
    app = core.App()

    # User specified variables, queryable as Python Object
    install_props = json.loads(json.dumps(get_install_properties()), object_hook=lambda d: SimpleNamespace(**d))
    user_specified_variables = json.loads(json.dumps({
        "bucket": install_props.Config.bucket,
        "region": app.node.try_get_context("region"),
        "base_os": app.node.try_get_context("base_os"),
        "ldap_user": app.node.try_get_context("ldap_user"),
        "ldap_password": app.node.try_get_context("ldap_password"),
        "ssh_keypair": app.node.try_get_context("ssh_keypair"),
        "client_ip": app.node.try_get_context("client_ip"),
        "custom_ami": app.node.try_get_context("custom_ami"),
        "ebs_snap": app.node.try_get_context("ebs_snap"),
        "cluster_id": app.node.try_get_context("cluster_id"),
        "vpc_cidr": app.node.try_get_context("vpc_cidr"),
        "china_region": True if app.node.try_get_context("region") in ['cn-north-1', 'cn-northwest-1'] else False,
        "existing_vpc_azs": app.node.try_get_context("existing_vpc_azs"),
        "existing_vpc_id": app.node.try_get_context("existing_vpc_id"),
        "existing_vpc_cidr": app.node.try_get_context("existing_vpc_cidr"),
        "existing_public_subnets": app.node.try_get_context("existing_public_subnets"),
        "existing_private_subnets": app.node.try_get_context("existing_private_subnets")
    }), object_hook=lambda d: SimpleNamespace(**d))

    principals_suffix = {"backup": f"backup.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}",
                         "cloudwatch": f"cloudwatch.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}",
                         "ec2": f"ec2.{core.Aws.URL_SUFFIX}",
                         "lambda": f"lambda.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}",
                         "sns": f"sns.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}",
                         "spotfleet": f"spotfleet.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}",
                         "ssm": f"ssm.{core.Aws.URL_SUFFIX if user_specified_variables.china_region is False else 'amazonaws.com'}"}
    
    # Apply default tag to all taggable resources
    core.Tags.of(app).add("soca:ClusterId", user_specified_variables.cluster_id)
    core.Tags.of(app).add("soca:CreatedOn", str(datetime.datetime.utcnow()))
    core.Tags.of(app).add("soca:CreatedFrom", user_specified_variables.client_ip)
    core.Tags.of(app).add("soca:Version", install_props.Config.version)

    # Launch Cfn generation
    cdk_env = core.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                               region=user_specified_variables.region if user_specified_variables.region else os.environ['CDK_DEFAULT_REGION'])

    SOCAInstall(app, user_specified_variables.cluster_id, env=cdk_env,
                          description=f"SOCA cluster version {install_props.Config.version}",
                          termination_protection=install_props.Config.termination_protection)
    app.synth()
