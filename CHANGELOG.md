# 修改记录
## [2.5.1] - 2020-09-27
### 基于版本说明
本修改基于[Global 2.5.0](https://github.com/awslabs/scale-out-computing-on-aws/blob/master/CHANGELOG.md#250---2020-07-17)，国内地址为[https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.5.0/scale-out-computing-on-aws.template](https://soca-china-deployment.s3.cn-northwest-1.amazonaws.com.cn/scale-out-computing-on-aws/v2.5.0/scale-out-computing-on-aws.template)

### 修改内容
- 去掉EFS，使用EBS。外挂一个EBS卷作为/apps，目前为ext3格式；/data目录直接在Scheduler节点上创建
- 在Scheduler上做NFS，把/apps、/data共享
- Work Node把yum源修改为国内
- 分带ElasticSearch和不带ElasticSearch版本，默认带ElasticSearch，不带的有without-es后缀
- 汉化