# 安装SOCA
## 安装AWS CLI
### Windows
参见：https://docs.aws.amazon.com/zh_cn/cli/latest/userguide/install-windows.html#install-msi-on-windows
### Linux
参见：https://docs.aws.amazon.com/zh_cn/cli/latest/userguide/install-linux.html
## 配置访问密钥或者Role
## 安装node.js
### Windows
访问https://nodejs.org/ 下载安装包，如果已经安装，确保版本>=16.13.0。运行`node --version`
### Linux
```bash
wget https://nodejs.org/dist/v16.13.0/node-v16.13.0-linux-x64.tar.xz
tar xf node-v16.13.0-linux-x64.tar.xz
cd node-v16.13.0-linux-x64/
./bin/node -v
#解压文件的 bin 目录底下包含了 node、npm 等命令，使用 ln 命令来设置软连接
#自行修改/usr/software/nodejs/为实际目录
ln -s /usr/software/nodejs/bin/npm /usr/bin/
ln -s /usr/software/nodejs/bin/node /usr/bin/
```
## 安装CDK Toolkit
```
npm install -g aws-cdk
#自行修改/usr/software/nodejs/为实际目录
ln -s /usr/software/nodejs/bin/cdk /usr/bin/
#检查版本
cdk --version
```
## 安装Python3
自行安装
## 安装requirements
```
pip install -r requirements.txt -i https://opentuna.cn/pypi/web/simple/
```
## 部署
```
python3 install_soca.py
```
