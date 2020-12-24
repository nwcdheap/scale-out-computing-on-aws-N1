# 修改记录
## [2.6.1] - 2020-12-24
### 基于版本说明
本修改基于[Global 2.6.0](https://github.com/awslabs/scale-out-computing-on-aws/blob/master/CHANGELOG.md#260---2020-10-29)，国内地址为[https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.6.0/scale-out-computing-on-aws.template](https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.6.0/scale-out-computing-on-aws.template)

### 修改内容
- 使用自定义AMI作为Scheduler、Work Node启动AMI，加快启动速度
- 去掉EFS，使用EBS。外挂一个EBS卷作为/apps，目前为ext3格式；/data目录直接在Scheduler节点上创建
- 在Scheduler上做NFS，把/apps、/data共享
- Scheduler、Work Node、图形工作站的yum源、pip源修改为国内
- 去掉ElasticSearch，降低成本
- 汉化
## [2.5.1] - 2020-09-27
### 基于版本说明
本修改基于[Global 2.5.0](https://github.com/awslabs/scale-out-computing-on-aws/blob/master/CHANGELOG.md#250---2020-07-17)，国内地址为[https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.5.0/scale-out-computing-on-aws.template](https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.5.0/scale-out-computing-on-aws.template)

### 修改内容
- 去掉EFS，使用EBS。外挂一个EBS卷作为/apps，目前为ext3格式；/data目录直接在Scheduler节点上创建
- 在Scheduler上做NFS，把/apps、/data共享
- Work Node把yum源修改为国内
- 分带ElasticSearch和不带ElasticSearch版本，默认带ElasticSearch，不带的有without-es后缀
- 汉化