# 使用手册
SOCA是AWS基于自身在工程仿真分析平台的构建和使用中积累的经验，推出的开源端到端高性能计算（HPC）平台解决方案。SOCA是一种可帮助客户轻松部署和操作多用户环境，从而支持计算机辅助工程 (CAE) 等计算密集型工作流的解决方案。该解决方案具有多种可选的计算资源、快速网络主干、无限存储空间以及直接集成在 AWS 中的预算和成本管理。该解决方案部署了提供云工作站、文件管理和自动化工具的用户界面 (UI)，您可以创建自己的队列、调度程序资源、Amazon 系统映像 (AMI) 以及用于用户和组权限的管理功能。
## 如何部署SOCA平台
部署此解决方案将在AWS Cloud中构建以下环境。
![](images/01.png) 
该解决方案的核心在于实现计划程序 Amazon Elastic Compute Cloud (Amazon EC2) 实例，以利用 AWS CloudFormation 和 Amazon EC2 Auto Scaling 自动启动执行集群用户任务（如扩展计算任务和远程虚拟会话）所需的资源。
此外，该解决方案还会部署 Amazon Elastic File System (Amazon EFS) 或通过EBS以NFS方式实现永久存储；AWS Lambda 函数用于验证所需满足的前提条件并为 Application Load Balancer (ALB) 创建一个默认的已签署证书以管理对 Desktop Cloud Visualization (DCV) 工作站会话的访问；Amazon Elasticsearch Service (Amazon ES) 集群用于存储任务和托管信息（可选）；以及 AWS Secrets Manager 用于存储解决方案配置文件。该解决方案还会利用 AWS Identity and Access Management (IAM) 角色强制执行最低特权访问。
SOCA使用AWS CloudFormation 模板以部署基础架构组件，AWS服务，操作系统和管理软件以及自定义逻辑脚本，可实现一键式部署。  
CloudFormation地址：https://nwcd-samples.s3.cn-northwest-1.amazonaws.com.cn/soca/v2.6.4/templates/scale-out-computing-on-aws-without-es.template
 

如果您已有AWS中国区域的账号，只需点击进入Cloudfomation服务控制台，`创建堆栈`
![](images/02.png) 
在“指定堆栈详细信息”页面填写部署SOCA所需信息：  
“堆栈名称”：（用户自定义）  
“Linux Distro”: 选择SOCA解决方案中所有EC2实例的操作系统，可在Centos7（默认），Redhat7，AmazonLinux三个操作系统中选择。可保持默认。  
“AppsEBSSnap”：如果已有安装好仿真软件的EBS存储盘快照，可以直接输入快照id（snap-××××××××），无需重新安装。如果没有保持默认，创建空的共享EBS存储盘。  
“Instance type for your master host”：设置主节点实例类型，可保持默认。  
“Create your new VPC”：设置SOCA所在VPC的私有IP地址范围，可保持默认。  
“What's your IP?”：设置可访问SOCA平台的IP地址范围。不要设置为0.0.0.0/0  
“What's your SSH keypair?”：选择您在中国宁夏区域已有的SSH密匙对，如果没有请先在EC2控制台中创建。  
“Username for your default LDAP user”：登录SOCA平台的初始用户名（用户自定义）   
“Password for your default LDAP user”：登录SOCA平台的初始密码（用户自定义）  
点击`下一步`->`下一步  `
在`审核`页面勾选最下方的2个复选框，点击`创建堆栈` 
![](images/03.png) 
等待30分钟左右，堆栈创建完成，点击根堆栈，选择“输出”选项卡，点击WebUserInterface链接.
![](images/04.png) 
输入部署时设置的用户名和密码登录，即可进入SOCA平台主页面。
![](images/05.png) 
## 如何访问SOCA平台
您可以使用DCV（桌面云可视化）或通过SSH访问SOCA平台。
### SSH访问
要使用SSH协议访问SOCA平台，只需单击左侧导航栏中的“ SSH访问”，然后按照说明进行操作。您可以从SOCA平台下载PEM或PPK格式的私钥用于连接。
![](images/06.png) 

### 使用DCV进行图形访问
要使用完整的远程桌面体验访问SOCA平台，请单击左侧导航栏中的“图形工作站访问”。默认情况下，您被授权最多同时建立4个图形工作站会话（EC2实例）。
![](images/07.png) 
设置图形工作站的运行时长和实例类型。点击“创建会话#”即可启动图形工作站会话的创建进程。
会话准备就绪后，该消息将自动更新为连接信息
![](images/08.png) 
可以点击“直接从浏览器打开会话”通过浏览器访问图形工作站的远程桌面。也可以下载DCV客户端软件，通过客户端访问图形工作站，以获得更佳的远程桌面操作体验。
![](images/09.png) 

## 如何配置SOCA平台
### 安装仿真软件
具体参考各仿真软件的安装指南，注：所有软件均需安装在/apps目录下。
### 管理队列
#### 1.新建/删除队列
SOCA平台默认创建了4个队列：high，normal (缺省)，low 和 alwayson。  
您也可以根据自己的需要创建新的队列或删除已有的队列。点击左侧导航栏的“队列管理”菜单。
![](images/10.png) 
在“创建队列”选项卡中输入队列名称，选择队列的模式（Automatic Provisioning和Always On模式）  
Automatic Provisioning——此队列中的主机将基于排队任务的数量自动启动，主机只能由特定ID的作业使用，并在作业完成后自动终止.  
Always On——此队列中的主机将始终在线，直到管理员将其手动终止  
点击“创建队列”即可在调度系统中新建一个队列。  
在“删除队列”选项卡中选择要删除的队列，勾选复选框，点击“删除队列”即可删除已有队列。  

#### 2.设置队列参数
根据需要修改下面队列配置文件，以更改队列参数。
`sudo nano /apps/soca/cluster_manager/settings/queue_mapping.yml`

- 设置新建Automatic Provisioning模式队列的配置参数
    - 选项1：使用与现有队列相同的设置。在这种情况下，只需使用新队列更新队列数组。
![](images/11.png) 
    - 选项2：设置特定配置参数。在这种情况下，您首先需要在YAML文件上创建一个新队列类型，如下图中新加memory类型。
![](images/12.png) 
    - 然后，以root身份，在调度器主节点上添加一个新的crontab。使用-c参数指定队列配置YAML文件的路径，-t参数指定您刚创建的队列类型名称。
```
*/3 * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3
/apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c
/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t memory
```

- 设置新建Always on模式队列的基础设施资源  
如果你新建的队列选择的是Always on模式，则需要手动的启动或关闭此队列所运行的基础设施资源。
    - 启动基础设施资源：  
运行python3 apps/soca/cluster_manager/add_nodes.py并启用--keep_forever True标识
```
# Launch 1 c5.large always on
python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py --instance_type c5.large \
    --desired_capacity 1 \
    --queue <queue_name> \
    --job_name instancealwayson \
    --job_owner mcrozes \
    --keep_forever True
```

    - 删除资源：  
只需转到您的CloudFormation控制台，按照命名约定找到堆栈：soca- cluster-name -keepforever- queue_name -uniqueid并终止它。
![](images/13.png) 
- 限制谁可以提交工作  
仅允许特定的个人用户或/和LDAP组提交作业。您可以同时配置allowed_users或excluded_users来管理每个队列的ACL 
![](images/14.png) 
在此示例中，user1可以将作业提交到“普通”队列，但不能提交到“高”或“低”队列。
![](images/15.png) 
在此示例中，user1是唯一有权提交作业的用户。
- 限制可以配置哪种类型的EC2实例  
控制可以为任何给定队列设置哪种类型的EC2实例。您可以同时配置allowed_instance_types和excluded_instance_types来管理每个队列允许的EC2实例类型。
![](images/16.png) 
在此示例中，只有c5和c5n系列中的EC2实例类型可用于提交到普通队列的作业。对于测试队列，仅允许使用c5.4xlarge实例类型。
- 限制并发作业或启动的实例数量
![](images/17.png) 
在此示例中，“ myqueue”并发作业的最大数量为5。同时，作业不能请求超过10个实例

## 如何管理应用程序
不同的仿真应用程序具有不同的执行命令脚本和输入参数，可以在SOCA平台创建应用程序配置文件，通过简单的拖拽方式HPC管理员可以直观的、所见即所得的来构建自己的表单，而无需任何编码/ HTML经验。以使平台应用用户能够通过简单的Web界面提交HPC作业。
### 创建应用
规划仿真应用的输入参数有哪些，从而确定输入参数表单的内容。  
点击左侧导航栏中的“应用管理”菜单，选择“创建新应用”选项卡。在“步骤1：设计参数表单“选项卡中开始构建HTML表单。
![](images/18.png) 
如：从右侧组件列表中拖动“文本字段”组件，以将其添加到表单。  
配置widget，将关联的变量名（在此示例中为job_name）设置为名称（红色方框部分）。  
在下面的示例中，用户在job_name 中输入的值将被发送到作业脚本并通过 ％job_name％读取。
![](images/19.png) 
重复其它参数的设置，可灵活选择不同的组件类型，如下拉框，复选框，文本输入框等。  
点击“步骤2：设计作业脚本”选项卡，输入作业执行脚本。
![](images/20.png) 
点击“步骤3：更新应用设置”给新建的应用命名，并选择相应的图片作为此应用在SOCA平台应用列表中显示的缩略图。点击“更新此应用”之后SOCA平台的用户就可以直接在应用列表中选择并点击相应的图标执行应用程序。
![](images/21.png) 
![](images/22.png) 

## 如何管理用户/组及相应的权限
注：用户和组管理仅限于管理员用户  
点击左侧导航栏中的“用户管理”和“组群管理”菜单。  
![](images/23.png) 
### 新建用户
要创建新用户，只需填写“添加新用户”表单。通过选中“启用Sudo访问”复选框来选择用户是否为管理员。如果需要，您还可以手动强制UID / GID。
### 删除用户
要删除用户，请导航至“删除用户”部分，然后选择要删除的用户并选中复选框
### 重置给定用户的密码
用户可以通过Web ui更改自己的密码。如果需要，管理员还可以通过代表用户重置密码来临时解锁用户。
### 管理SUDO（管理员权限）
管理员可以为任何用户授予/撤消SUDO权限：
![](images/24.png) 
### 创建一个新组
要创建新组，只需选择“创建组”，然后选择要添加到该组的用户
![](images/25.png) 
### 查找用户组成员
您可以通过转到“查找组成员”选项卡来查找成员所在组。
### 变更群组成员
如果需要，您可以添加/删除给定组中的用户。
### 删除群组
最后，要删除组，只需导航至“删除组”选项卡。
## 设置分析功能
SOCA平台在运行过程中产生许多指标值（作业计数，计算节点计数，使用的计算节点类型，仿真时间，仿真计算价格等），能够将这些指标值实时转换为有意义的数据对于保持组织的敏捷性非常重要。SOCA可以利用 AWS支持的分析，报表和商业智能工具来实现对HPC平台的实时洞察。  
如果选择带有ElasticSearch功能的Cloudfomation模板部署后，SOCA平台自动将产生的带有各种标签的日志信息发送至AWS ElasticSearch服务，以用于检索和分析。同时SOCA平台还可以集成Metricbeat轻量级软件来定期从操作系统和服务器上运行的服务收集指标。  
注：默认情况下，MetricBeat是禁用的。要启用它，可以使用提交作业 -l system_metrics=True或在队列级别启用此参数。启用此功能后，SOCA将在为您的作业启动的所有计算节点上自动安装和配置MetricBeat。  
### 如何使用分析平台
点击左侧导航栏中的“集群分析指标”菜单。可以看到SOCA平台关联的AWS ElasticSearch分析平台的控制台链接。点击链接访问AWS ElasticSearch控制台。

#### 1.创建索引
点击左侧导航栏中的“Management”菜单，然后点击“Index Patterns”
![](images/26.png) 
输入pbsnodes *创建您的第一个索引。
![](images/27.png) 
单击“下一步”，然后选择“timestamp”。完成后，单击“Create Index Pattern”。
![](images/28.png) 
对jobs*索引重复相同的操作。
![](images/29.png) 
这次，选择start_iso作为时间过滤器键。
![](images/30.png) 
配置完索引后，转到Kibana，选择“Discover”选项卡以开始可视化数据。
![](images/31.png) 
![](images/32.png) 
#### 2.创建分析仪表板
点击Kibana导航栏中的“Visualize”以创建新的可视化。
如分析按实例类型分类的每用户作业数量统计分析。
![](images/33.png) 
![](images/34.png) 
 
#### 3.使用仪表板进行分析
点击Kibana导航栏中的“Dashboard”以查看分析仪表板。如果之前有启动MetricBeat功能，则MetricBeat将自动集成到ElasticSearch集群。可以在仪表板中看到MetricBeat生成的报表。
![](images/35.png) 
如“Host Overview ECS”仪表板将为您提供与按作业，用户或队列启动的计算节点有关的系统信息。默认情况下，ELK报告“过去15分钟”数据
![](images/36.png) 
您可以按作业ID，作业所有者，队列，进程名称或主机IP筛选结果。请参见下面的示例，该示例返回作业19544的指标信息。
![](images/37.png) 
#### 4.利用AWS Cost Explorer服务进行成本分析。
由SOCA启动的任何EC2资源都附带有详尽的EC2标签列表，可用于获取有关群集使用情况的详细信息。列表包括（但不限于）：
- 项目名称
- 工作负责人
- 工作名称
- 作业队列
- 工作编号

这些是默认标签，您可以根据需要添加自己的标签。
##### 步骤1：启用费用分配标签
点击您的帐户名（1），然后选择“我的结算信息中心”（2）
![](images/38.png) 
然后点击“费用分配标签”
![](images/39.png) 
最后，搜索所有“ SOCA”标签，然后单击“激活”
![](images/40.png) 
##### 步骤2：启用Cost Explorer
在结算信息中心中，选择“费用管理器”（1），然后单击“启用费用管理器”（2）。
![](images/41.png) 
##### 步骤3：查询Cost Explorer
打开“费用浏览器”标签，然后指定过滤器。在此示例中，我要获取名为“ cpus”的队列（2）的EC2成本（1），按天分组。
![](images/42.png) 
要获取更多详细信息，请选择 'Group By'并应用其他过滤器。例如，如果希望看到“ cpus”队列的用户级别信息，请单击“Group By”水平标签（1）下的“标签”部分，然后选择“ soca：JobOwner”标签。用户的“ cpus”队列将按费用明细自动更新您的图表
![](images/43.png) 

## 使用自定义域名通过https访问
直接使用CloudFormation输出的ALB地址访问时，浏览器会提示访问不安全，这是因为没有正确配置https的证书。  
### 步骤1、配置AWS Certificate Manager(ACM)证书
进入[ACM](https://cn-northwest-1.console.amazonaws.cn/acm/home?region=cn-northwest-1)控制台。
#### 方式1、在AWS内申请
点击`请求证书`，选择`请求公有证书`，再点击`请求证书`，输入域名，点击`下一步`，根据自身情况选择验证方式。验证通过后，即可在证书管理里看到对应的证书。
#### 方式2、已有证书/导入证书
点击`导入证书`，在对应的框中，粘贴对应的内容即可。
### 步骤2、ALB选择ACM证书
进入[负载均衡器控制台](https://cn-northwest-1.console.amazonaws.cn/ec2/v2/home?region=cn-northwest-1#LoadBalancers:sort=loadBalancerName)，找到SOCA的负载均衡器，选中，然后点击`侦听器`页签，选择`HTTPS:443`对应的`查看/编辑证书`，点击`Certificates`右边的`+`按钮，选择上一节申请或导入的证书，再点击`add`。
### 步骤3、修改自定义域名的CNAME
进入客户自己的域名管理控制台，设置域名解析，把CNAME指向ALB的DNS名称即可。
### 步骤4、验证
在浏览器中，使用`https://自定义域名`访问。
![](./images/https.png)
