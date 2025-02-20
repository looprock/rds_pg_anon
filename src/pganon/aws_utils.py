import os
from .loglib import log_json
import boto3
import json
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
import random
import string

class AWSUtils:
    def rds_env_var_to_options(self) -> dict:
        result_dict = {}
        env_vars = os.environ
        # this is the list of options that are available for the DB instance
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/restore_db_instance_from_db_snapshot.html

        db_env_var_dict = {
            "DBINSTANCEIDENTIFIER": {"option": "DBInstanceIdentifier", "type": "string"},
            "DBSNAPSHOTIDENTIFIER": {"option": "DBSnapshotIdentifier", "type": "string"},
            "DBINSTANCECLASS": {"option": "DBInstanceClass", "type": "string"},
            "PORT": {"option": "Port", "type": "interger"},
            "AVAILABILITYZONE": {"option": "AvailabilityZone", "type": "string"},
            "DBSUBNETGROUPNAME": {"option": "DBSubnetGroupName", "type": "string"},
            "MULTIAZ": {"option": "MultiAZ", "type": "boolean"},
            "PUBLICLYACCESSIBLE": {"option": "PubliclyAccessible", "type": "boolean"},
            "AUTOMINORVERSIONUPGRADE": {"option": "AutoMinorVersionUpgrade", "type": "boolean"},
            "LICENSEMODEL": {"option": "LicenseModel", "type": "string"},
            "DBNAME": {"option": "DBName", "type": "string"},
            "ENGINE": {"option": "Engine", "type": "string"},
            "IOPS": {"option": "Iops", "type": "integer"},
            "OPTIONGROUPNAME": {"option": "OptionGroupName", "type": "string"},
            "TAGS": {"option": "Tags", "type": "key_list"},
            "STORAGETYPE": {"option": "StorageType", "type": "string"},
            "TDECREDENTIALARN": {"option": "TdeCredentialArn", "type": "string"},
            "TDECREDENTIALPASSWORD": {"option": "TdeCredentialPassword", "type": "string"},
            "VPCSECURITYGROUPIDS": {"option": "VpcSecurityGroupIds", "type": "list"},
            "DOMAIN": {"option": "Domain", "type": "string"},
            "DOMAINFQDN": {"option": "DomainFqdn", "type": "string"},
            "DOMAINOU": {"option": "DomainOu", "type": "string"},
            "DOMAINAUTHSECRETARN": {"option": "DomainAuthSecretArn", "type": "string"},
            "DOMAINDNSIPS": {"option": "DomainDnsIps", "type": "list"},
            "COPYTAGSTOSNAPSHOT": {"option": "CopyTagsToSnapshot", "type": "boolean"},
            "DOMAINIAMROLENAME": {"option": "DomainIAMRoleName", "type": "string"},
            "ENABLEIAMDATABASEAUTHENTICATION": {"option": "EnableIAMDatabaseAuthentication", "type": "boolean"},
            "ENABLECLOUDWATCHLOGSEXPORTS": {"option": "EnableCloudwatchLogsExports", "type": "list"},
            "PROCESSORFEATURES": {"option": "ProcessorFeatures", "type": "name_list"},
            "USEDEFAULTPROCESSORFEATURES": {"option": "UseDefaultProcessorFeatures", "type": "boolean"},
            "DBPARAMETERGROUPNAME": {"option": "DBParameterGroupName", "type": "string"},
            "DELETIONPROTECTION": {"option": "DeletionProtection", "type": "boolean"},
            "ENABLECUSTOMEROWNEDIP": {"option": "EnableCustomerOwnedIp", "type": "boolean"},
            "CUSTOMIAMINSTANCEPROFILE": {"option": "CustomIamInstanceProfile", "type": "string"},
            "BACKUPTARGET": {"option": "BackupTarget", "type": "string"},
            "NETWORKTYPE": {"option": "NetworkType", "type": "string"},
            "STORAGETHROUGHPUT": {"option": "StorageThroughput", "type": "integer"},
            "DBCLUSTERSNAPSHOTIDENTIFIER": {"option": "DBClusterSnapshotIdentifier", "type": "string"},
            "ALLOCATEDSTORAGE": {"option": "AllocatedStorage", "type": "integer"},
            "DEDICATEDLOGVOLUME": {"option": "DedicatedLogVolume", "type": "boolean"},
            "CACERTIFICATEIDENTIFIER": {"option": "CACertificateIdentifier", "type": "string"},
            "ENGINELIFECYCLESUPPORT": {"option": "EngineLifecycleSupport", "type": "string"},
        }

        # string, integer, boolean, list, key_list, name_list
        for key, value in env_vars.items():
            check_key = key.split("PGANON_RDS_")[-1]
            if check_key in db_env_var_dict:
                if check_key in db_env_var_dict:
                    # string values: "value"
                    if db_env_var_dict[check_key]["type"] == "string":
                        result_dict[db_env_var_dict[check_key]["option"]] = value
                    # integer values: 128, 1024, 2048, etc.
                    elif db_env_var_dict[check_key]["type"] == "integer":
                        result_dict[db_env_var_dict[check_key]["option"]] = int(value)
                    # boolean values: true, false
                    elif db_env_var_dict[check_key]["type"] == "boolean":
                        result_dict[db_env_var_dict[check_key]["option"]] = value.lower() == "true"
                    # list values: Value,Value,Value
                    elif db_env_var_dict[check_key]["type"] == "list":
                        result_dict[db_env_var_dict[check_key]["option"]] = value.split(",")
                    # key_list/name_list values: Key=Value,Key=Value,Key=Value
                    elif db_env_var_dict[check_key]["type"] == "key_list" or db_env_var_dict[check_key]["type"] == "name_list":
                        dict_list = []
                        # this kind of thing is why I hate the AWS SDK
                        if db_env_var_dict[check_key]["type"] == "key_list":
                            key_name = "Key"
                        else:
                            key_name = "Name"
                        values = value.split(",")
                        for val in values:
                            dl_key, dl_value = val.split("=")
                            dict_list.append({key_name: dl_key, "Value": dl_value})
                        result_dict[db_env_var_dict[check_key]["option"]] = dict_list
        return result_dict

    def download_from_s3(self, bucket_name: str, file_name: str, destination_file: str = None) -> bool:
        s3 = boto3.client('s3')
        try:
            output_file = file_name
            if destination_file:
                output_file = destination_file
            s3.download_file(bucket_name, file_name, output_file)
            log_json(f"Downloaded {file_name} from S3 bucket {bucket_name} to {output_file}")
            return True
        except Exception as e:
            log_json(f"Failed to download {file_name} from S3: {e}. Do you need to use --initialize?", level='error')
            return False

    def upload_to_s3(self,bucket_name: str, file_name: str) -> None:
        s3 = boto3.client('s3')
        try:
            s3.upload_file(file_name, bucket_name, file_name)
            log_json(f"Uploaded {file_name} to S3 bucket {bucket_name}")
        except Exception as e:
            log_json(f"Failed to upload {file_name} to S3: {e}", level='error')
            exit(1)

    def get_rds_host_by_instance_id(self, instance_id: str, region_name: str) -> str:
        """Retrieve the endpoint (host) of an RDS instance by its instance ID."""
        try:
            # Create a boto3 RDS client
            rds_client = boto3.client('rds', region_name=region_name)

            # Describe the RDS instance
            response = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)

            # Extract the endpoint address
            endpoint = response['DBInstances'][0]['Endpoint']['Address']
            return endpoint

        except rds_client.exceptions.DBInstanceNotFoundFault:
            raise Exception(f"RDS instance with ID '{instance_id}' not found.")
        except NoCredentialsError:
            raise Exception("AWS credentials not found. Please configure your credentials.")
        except PartialCredentialsError:
            raise Exception("Incomplete AWS credentials. Please check your configuration.")
        except Exception as e:
            raise Exception(f"An error occurred: {e}")


    def create_instance_from_latest_snapshot(self, instance_id: str, region_name: str, user_name: str, password: str) -> None:
        """Create a new RDS instance from the latest snapshot of an existing RDS instance."""
        rds_client = boto3.client('rds', region_name=region_name)

        try:
            # Get all snapshots for the given instance
            snapshots = rds_client.describe_db_snapshots(DBInstanceIdentifier=instance_id, SnapshotType='automated')

            # Find the latest snapshot
            latest_snapshot = max(snapshots['DBSnapshots'], key=lambda x: x['SnapshotCreateTime'])

            # Get details of the existing instance
            instance_details = rds_client.describe_db_instances(DBInstanceIdentifier=instance_id)
            instance_info = instance_details['DBInstances'][0]
            # set default parameters
            # if new_instance_id is not provided, use a default
            random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
            new_instance_id = f"dbinspect-{random_string.lower()}-{instance_id}"
            # set the instance type to a small instance
            instance_class_parts = instance_info['DBInstanceClass'].split('.')
            instance_class_base = ".".join(instance_class_parts[:2])
            new_instance_type = f"{instance_class_base}.small"

            vpc_security_group_ids = []
            for group in instance_info['VpcSecurityGroups']:
                if group['Status'] == 'active':
                    vpc_security_group_ids.append(group['VpcSecurityGroupId'])

            pganon_tags = [
                {
                    'Key': 'function',
                    'Value': 'pganon temp instance'
                },
            ]

            restore_params = {
                "DBInstanceIdentifier": new_instance_id,
                "DBSnapshotIdentifier": latest_snapshot['DBSnapshotIdentifier'],
                "DBInstanceClass": new_instance_type,
                "MultiAZ": False,
                "PubliclyAccessible": False,
                "DeletionProtection": False,
                "AllocatedStorage": instance_info['AllocatedStorage'],
                "Engine": instance_info['Engine'],
                "Port": instance_info['Endpoint']['Port'],
                "DBSubnetGroupName": instance_info['DBSubnetGroup']['DBSubnetGroupName'],
                "VpcSecurityGroupIds": vpc_security_group_ids,
            }

            # if alt_args are provided, update the instance_info with the alt_args
            alt_args = self.rds_env_var_to_options()
            if alt_args:
                for alt_arg_key, alt_arg_value in alt_args.items():
                    restore_params[alt_arg_key] = alt_arg_value

            # add the pganon tags
            if "Tags" in restore_params:
                restore_params["Tags"].append(pganon_tags)
            else:
                restore_params["Tags"] = pganon_tags

            # Create a new instance from the latest snapshot
            rds_client.restore_db_instance_from_db_snapshot(**restore_params)

            log_json(f"Creating new RDS instance {new_instance_id} from snapshot {latest_snapshot['DBSnapshotIdentifier']}.")

            # Wait for the new instance to become available
            waiter = rds_client.get_waiter('db_instance_available')
            waiter.wait(DBInstanceIdentifier=new_instance_id)
            log_json(f"RDS instance {new_instance_id} is now available.")
            # get the endpoint of the new instance
            new_instance_details = rds_client.describe_db_instances(DBInstanceIdentifier=new_instance_id)
            # disable automated backups since this is just a temp instance
            # Disabled due to: enabling and disabling backups can result in a brief I/O suspension that lasts from a few seconds to a few minutes, depending on the size and class of your DB instance.
            # rds_client.modify_db_instance(
            #     DBInstanceIdentifier=new_instance_id,
            #     BackupRetentionPeriod=0,
            #     ApplyImmediately=True
            # )
            if 'KmsKeyId' in new_instance_details['DBInstances'][0]:
                kms_key_id = new_instance_details['DBInstances'][0]['KmsKeyId']
            else:
                kms_key_id = None
            return {
                "id": new_instance_id,
                "endpoint": new_instance_details["DBInstances"][0]["Endpoint"]["Address"],
                "port": new_instance_details["DBInstances"][0]["Endpoint"]["Port"],
                "username": user_name,
                "password": password,
                "kms_key_id": kms_key_id
            }

        except ClientError as e:
            log_json(f"Failed to create new RDS instance from snapshot: {e}", level='error')

    def save_secret_to_aws(self, secret_name: str, secret_data: dict) -> None:
        # Save the database connection information to AWS Secrets Manager
        client = boto3.client('secretsmanager')
        try:
            # Check if the secret already exists
            client.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_data)
            )
            log_json(f"Secret {secret_name} created successfully.", level='info')
        except client.exceptions.ResourceExistsException:
            # If the secret exists, update it
            client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_data)
            )
            log_json(f"Secret {secret_name} updated successfully.", level='info')
        except Exception as e:
            log_json(f"Failed to save secret {secret_name}: {e}", level='error')

    def create_db_snapshot(self, instance_id: str, snapshot_id: str) -> None:
        """Create a snapshot of the specified RDS instance."""
        rds_client = boto3.client('rds')

        try:
            # Check if the snapshot already exists
            try:
                existing_snapshots = rds_client.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
            except ClientError as e:
                if e.response['Error']['Code'] == 'DBSnapshotNotFound':
                    log_json(f"Snapshot {snapshot_id} not found, proceeding to create a new one.", level='info')
                else:
                    log_json(f"Failed to describe snapshot: {e}", level='error')
                    return
            if existing_snapshots['DBSnapshots']:
                # If it exists, delete the existing snapshot
                rds_client.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
                log_json(f"Deleted existing snapshot {snapshot_id} before creating a new one.")

            rds_client.create_db_snapshot(
                DBSnapshotIdentifier=snapshot_id,
                DBInstanceIdentifier=instance_id
            )
            log_json(f"Snapshot {snapshot_id} creation initiated for instance {instance_id}.")

            # Wait for the snapshot to become available
            waiter = rds_client.get_waiter('db_snapshot_completed')
            waiter.wait(DBSnapshotIdentifier=snapshot_id)

            log_json(f"Snapshot {snapshot_id} created successfully for instance {instance_id}.")
        except ClientError as e:
            log_json(f"Failed to create snapshot: {e}", level='error')
            exit(1)

    def delete_instance(self, instance_id: str, snapshot_id: str) -> dict:
        try:
            rds_client = boto3.client('rds')
            # Create a final snapshot before deletion
            rds_client.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=False, FinalDBSnapshotIdentifier=snapshot_id)
            waiter = rds_client.get_waiter('db_snapshot_completed')
            waiter.wait(DBSnapshotIdentifier=snapshot_id)
            snapshot_info = rds_client.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
            snapshot_arn = snapshot_info['DBSnapshots'][0]['DBSnapshotArn']
            log_json(f"Deleted RDS instance {instance_id}, final snapshot {snapshot_id} created.")
            return {"snapshot_arn": snapshot_arn}
        except ClientError as e:
            log_json(f"Failed to delete RDS instance {instance_id}: {e}", level='error')
            exit(1)

    def delete_snapshot_if_exists(self, snapshot_id: str) -> None:
        """Create a snapshot of the specified RDS instance."""
        rds_client = boto3.client('rds')
        # Check if the snapshot already exists
        existing_snapshots = None
        try:
            existing_snapshots = rds_client.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBSnapshotNotFound':
                log_json(f"Snapshot {snapshot_id} not found, proceeding to create a new one.", level='info')
            else:
                log_json(f"Failed to describe snapshot: {e}", level='error')
                return
        if existing_snapshots:
            if 'DBSnapshots' in existing_snapshots and existing_snapshots['DBSnapshots']:
                # If it exists, delete the existing snapshot
                rds_client.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
                log_json(f"Deleted existing snapshot {snapshot_id} before creating a new one.")