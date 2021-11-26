# 安装SOCA
## 安装AWS CLI
### Windows
参见：https://docs.aws.amazon.com/zh_cn/cli/latest/userguide/install-windows.html#install-msi-on-windows
### Linux
参见：https://docs.aws.amazon.com/zh_cn/cli/latest/userguide/install-linux.html
## 配置访问密钥或者Role
## 安装node.js
### Windows
访问https://nodejs.org/下载安装包，如果已经安装，确保版本>=10.3.0。运行`node –version`
### Linux
```bash
wget https://nodejs.org/dist/v16.13.0/node-v16.13.0-linux-x64.tar.xz
tar xf  node-v16.13.0-linux-x64.tar.xz       // 解压
cd node-v10.9.0-linux-x64/                  // 进入解压目录
./bin/node -v                               // 执行node命令 查看版本
#解压文件的 bin 目录底下包含了 node、npm 等命令，我们可以使用 ln 命令来设置软连接：
ln -s /usr/software/nodejs/bin/npm /usr/local/bin/
ln -s /usr/software/nodejs/bin/node /usr/local/bin/
```
## 安装CDK Toolkit
运行`npm install -g aws-cdk`安装CDK Toolkit。然后检查版本`cdk –version`
## 安装Python3
## 创建virtualenv:
```
$ python -m venv .env
```
## 进入virtualenv
### Linux
```
$ source .env/bin/activate
```
### Windows
```
% .env\Scripts\activate.bat
```
## 安装requirements
```
$ pip install -r requirements.txt -i https://opentuna.cn/pypi/web/simple/
```
## 部署
```
$ python3 install_soca.py
```
