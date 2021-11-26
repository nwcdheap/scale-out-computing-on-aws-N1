#!/bin/bash -xe

export PATH=$PATH:/usr/local/bin

# Variable will be replaced by CDK
S3_BUCKET="%%S3_BUCKET%%"
S3InstallFolder="%%S3_BUCKET_FOLDER%%"
CLUSTER_ID="%%CLUSTER_ID%%"
SOCA_VERSION="%%SOCA_VERSION%%"
SOCA_INSTALL_AMI="%%SOCA_INSTALL_AMI%%"
SOCA_BASE_OS="%%BASE_OS%%"
LDAP_USERNAME="%%LDAP_USERNAME%%"
LDAP_PASSWORD="%%LDAP_PASSWORD%%"
SOCA_AUTH_PROVIDER="%%SOCA_AUTH_PROVIDER%%"
SOCA_LDAP_BASE="%%SOCA_LDAP_BASE%%"
RESET_PASSWORD_DS_LAMBDA="%%RESET_PASSWORD_DS_LAMBDA%%"
AWS_REGION="%%AWS_REGION%%"
PIP_CHINA_MIRROR="%%PIP_CHINA_MIRROR%%"
CENTOS_CHINA_REPO="%%CENTOS_CHINA_REPO%%"

# Install SSM
yum install -y https://nwcd-samples.s3.cn-northwest-1.amazonaws.com.cn/software/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent

if [[ "%%BASE_OS%%" == "centos7" ]]; then
  if [[ "$AWS_REGION" == "cn-north-1" ]] || [[ "$AWS_REGION" == "cn-northwest-1" ]]; then
    #usermod --shell /usr/sbin/nologin ec2-user
    curl -o /etc/yum.repos.d/CentOS-Base.repo $CENTOS_CHINA_REPO
  else
    usermod --shell /usr/sbin/nologin centos
  fi
fi

# Install awscli
if [[ "$SOCA_BASE_OS" == "centos7" ]] || [[ "$SOCA_BASE_OS" == "rhel7" ]]; then
  if [[ "$AWS_REGION" == "cn-north-1" ]] || [[ "$AWS_REGION" == "cn-northwest-1" ]]; then
    yum install -y python3-pip
    PIP=$(which pip3)
    $PIP install -i $PIP_CHINA_MIRROR awscli
    export PATH=$PATH:/usr/local/bin
  else
    yum install -y python3-pip
    PIP=$(which pip3)
    $PIP install awscli
    export PATH=$PATH:/usr/local/bin
  fi
fi

# Disable automatic motd update if using ALI
if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]]; then
  /usr/sbin/update-motd --disable
  rm /etc/cron.d/update-motd
  rm -f /etc/update-motd.d/*
fi

{
  echo export "SOCA_BASE_OS=\"$SOCA_BASE_OS\""
  echo export "SOCA_CONFIGURATION=\"$CLUSTER_ID\""
  echo export "AWS_DEFAULT_REGION=\"%%AWS_REGION%%\""
  echo export "SOCA_INSTALL_BUCKET=\"$S3_BUCKET\""
  echo export "SOCA_INSTALL_BUCKET_FOLDER=\"$S3InstallFolder\""
  echo export "SOCA_VERSION=\"$SOCA_VERSION\""
  echo export "SOCA_INSTALL_AMI=\"$SOCA_INSTALL_AMI\""
  echo export "SOCA_AUTH_PROVIDER=\"$SOCA_AUTH_PROVIDER\""
  echo export "SOCA_LDAP_BASE=\"$SOCA_LDAP_BASE\""
  echo export "LDAP_BASE=\"$SOCA_LDAP_BASE\""
} >> /etc/environment

source /etc/environment
AWS=$(command -v aws)

# Tag EBS disks manually as CFN  does not support it
AWS_AVAIL_ZONE=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone)
AWS_REGION="`echo \"$AWS_AVAIL_ZONE\" | sed "s/[a-z]$//"`"
AWS_INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
EBS_IDS=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" --region $AWS_REGION --query "Volumes[*].[VolumeId]" --out text | tr "\n" " ")
$AWS ec2 create-tags --resources $EBS_IDS --region $AWS_REGION --tags Key=Name,Value="$CLUSTER_ID Root Disk" "Key=soca:ClusterId,Value=$CLUSTER_ID"
EBS_IDS=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" Name=attachment.device,Values="/dev/sdb" --region $AWS_REGION --query "Volumes[*].[VolumeId]" --out text | tr "\n" " ")
$AWS ec2 create-tags --resources $EBS_IDS --region $AWS_REGION --tags Key=Name,Value="$CLUSTER_ID Apps Disk" "Key=soca:ClusterId,Value=$CLUSTER_ID"

# Tag Network Adapter for the Scheduler
ENI_IDS=$(aws ec2 describe-network-interfaces --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" --region $AWS_REGION --query "NetworkInterfaces[*].[NetworkInterfaceId]" --out text | tr "\n" " ")
$AWS ec2 create-tags --resources $ENI_IDS --region $AWS_REGION --tags Key=Name,Value="$CLUSTER_ID Scheduler Network Adapter" "Key=soca:ClusterId,Value=$CLUSTER_ID"

# Retrieve installer files from S3
echo "@reboot $AWS s3 cp s3://$S3_BUCKET/$S3InstallFolder/scripts/SchedulerPostReboot.sh /root && /bin/bash /root/SchedulerPostReboot.sh $S3_BUCKET $S3InstallFolder $LDAP_USERNAME '$LDAP_PASSWORD' >> /root/SchedulerPostReboot.log 2>&1" | crontab -
$AWS s3 cp s3://$S3_BUCKET/$S3InstallFolder/scripts/config.cfg /root/
$AWS s3 cp s3://$S3_BUCKET/$S3InstallFolder/scripts/requirements.txt /root/
$AWS s3 cp s3://$S3_BUCKET/$S3InstallFolder/scripts/Scheduler.sh /root/

# Specify the AD DS lambda function we will use to reset AD Password
if [[ "$SOCA_AUTH_PROVIDER" == "activedirectory" ]]; then
  if [[ "$RESET_PASSWORD_DS_LAMBDA" != "false" ]]; then
    echo "$RESET_PASSWORD_DS_LAMBDA" > /root/LambdaActiveDirectoryPasswordResetArn
  fi
fi


# Prepare Scheduler setup
/bin/bash /root/Scheduler.sh >> /root/Scheduler.sh.log 2>&1


