import argparse
import sys
import os
import boto3
import json
from botocore.exceptions import ProfileNotFound
import shutil
from shutil import make_archive, copytree
from colored import fg, attr
import yaml
from yaml.scanner import ScannerError
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


def upload_objects(install_directory, bucket, bucket_folder):
    # Upload required assets to customer S3 bucket
    print(f"\n====== Uploading install files to {bucket}/{bucket_folder} ======\n")
    dist_directory = f"{install_directory}/dist/"
    if os.path.isdir(dist_directory):
        print(f"{dist_directory} 文件夹存在，删除。")
        shutil.rmtree(dist_directory)
    os.makedirs(dist_directory)
    make_archive(f"{dist_directory}soca", "gztar", f"{install_directory}/../source/soca")
    copytree(f"{install_directory}/../source/scripts", f"{dist_directory}scripts/")

    try:
        install_bucket = s3.Bucket(bucket)
        for path, subdirs, files in os.walk(f"{dist_directory}"):
            path = path.replace("\\", "/")
            directory = path.split("/")[-1]
            for file in files:
                if directory:
                    upload_location = f"{bucket_folder}/{directory}/{file}"
                else:
                    upload_location = f"{bucket_folder}/{file}"
                print(f"{fg('green')}[+] Uploading {os.path.join(path, file)} to s3://{bucket}/{upload_location} {attr('reset')}")
                install_bucket.upload_file(os.path.join(path, file), upload_location)

    except Exception as upload_error:
        print(f"{fg('red')} Error during upload {upload_error}{attr('reset')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create SOCA installer")
    parser.add_argument("--profile", "-p", type=str, help="AWS CLI profile to use")
    args = parser.parse_args()
    if args.profile:
        try:
            session = boto3.session.Session(profile_name=args.profile)
        except ProfileNotFound:
            print(f"{fg('red')} Profile {args.profile} not found. Check ~/.aws/credentials file{attr('reset')}")
            sys.exit(1)
    else:
        session = boto3.session.Session()
    s3 = session.resource("s3")
    install_directory = os.path.dirname(os.path.realpath(__file__))
    os.chdir(install_directory)
    install_props = json.loads(json.dumps(get_install_properties()), object_hook=lambda d: SimpleNamespace(**d))
    bucket = install_props.Config.bucket
    bucket_folder = install_props.Config.bucket_folder
    upload_objects(install_directory,bucket,bucket_folder)