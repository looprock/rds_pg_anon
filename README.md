# pg_anon

Using the most current snapshot of a postgresql RDS instance, anonymize the data to another instance or a snapshot.

# Limitations

## snapshot

pg_anon requires a snapshot of the source instance.

## anonymization

The current implentation of this only deals with dictionary structures and doesn't support replacing keys or values inside lists outside of those specified in the 'lists' section.

While uniqueness is enforceable for basic column-level anonymized values, it's not enforced inside JSON columns.

# Usage

## installation

To install then environment and all it's dependencies, install [uv](https://docs.astral.sh/uv/) and run: `uv sync`

You should now be able to, either:
- source the environment using: `. ./.venv/bin/activate` then running `./pg_anon [arguments]`
- use: `uv run ./pg_anon [arguments]` 

## Required environment variables

- PGDATABASE: source database
- PGPASSWORD: source database instance password
- PGPORT: source database instance port
- PGUSER: source database instance user
- PGANON_ENVIRONMENT: A unique environment reference you can use to find resources created by pg_anon
- PGANON_RDS_SOURCE_ID: AWS instance ID of source database instance
- PGANON_S3_BUCKET_NAME: A bucket used to read and write state files

### Optional environment variables

- PGANON_CREDS_SECRET: a secret to write credentials information. (Default: /infra/[PGANON_ENVIRONMENT]/rds/pg-anon/credentials)
- PGANON_DATA_DIR: data directory to write output files to (Default: "./data")
- PGANON_DB_TIMEOUT: set the database connection timeout (Default: 30)
- PGANON_DB_RETRIES: set the number a times a database reconnection is attempted (Default: 10)
- PGANON_DB_BACKOFF_TIME: set the backoff start point in seconds, will double every attempt (Default: 1)
- PGANON_SAVE_DB: same as --savedb, This is primarily for testing and will cache the test database information and allow you run pganon against the same instance repeatedly.
- PGANON_SECRET_PROFILE: AWS profile to use to write secret. Setting this assumes --write-secret is true
- PGANON_SOURCE_AWS_REGION - the AWS region is identified via the boto session, but if that fails, or you wish to overwrite this, you can use this variable.
- PGANON_TARGET_AWS_REGION - the AWS region is identified via the boto session, but if that fails, or you wish to overwrite this, you can use this variable.

#### Optional RDS configuration

You can use the **all uppercase** name of the options [here](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/rds/client/restore_db_instance_from_db_snapshot.html), prefixed with 'PGANON_RDS_', to overwrite the parameters of the replica DB created by pganon. Depending on the input, you map them like:
  - string values: "value"
  - integer values: 128, 1024, 2048, etc.
  - boolean values: true, false
  - list values: Value,Value,Value
  - key_list (currently only Tags) / name_list values (currently only PROCESSORFEATURES): Key=Value,Key=Value,Key=Value

* for instance, you might want to consider:
    - export PGANON_RDS_VPCSECURITYGROUPIDS="sg-00000000000000000,sg-11111111111111111"
    - export PGANON_RDS_DBSUBNETGROUPNAME="test-security-group"


## Command Line Options

```
Options:
  --create-admin                Create a new admin user.
  --create-admin-user TEXT      Create a specific new admin user.
  --create-admin-password TEXT  Use a specific new admin user password: requires --create-admin-user.
  --download                    Download the file from S3 to the expected output name without processing.
  --dry-run                     Don't actually modify the database instance, just output the state changes.
  --initialize                  Initialize the file if it does not exist.
  --local-state                 Use the local state file instead of the remote state file.
  --overwrite                   Overwrite the output file if it already exists.
  --save                        Save the output file locally after processing.
  --savedb                      Save and re-use the database information.
  --secret-profile              Use a specific AWS profile for secret management. Setting this assumes --write-secret is true. (also configureable via PGANON_SECRET_PROFILE)
  --snapshot                    Save a snapshot and delete the instance. The snapshot will be created as 'pganon-[value of PGANON_ENVIRONMENT]' and will be overwritten by each run
  --upload                      Upload the existing state file to S3 without processing
  --verbose                     print verbose output
  --write-secret                Create a secret in AWS Secrets Manager. If PGANON_CREDS_SECRET is set, that will be used as the secret name, otherwise the secret name will be written to: 'infra/[value of PGANON_ENVIRONMENT]/rds/pg-anon/credentials'
  --help                        Show this message and exit.
```

# Outputs

By default, connection and resource information are written to a file: `./results_[PGANON_RDS_SOURCE_ID]_[PGANON_ENVIRONMENT].json`

If you used '--write-secret' or '--secret-profile' (or used related environment variables), the same data will be written to the specified secret as well.

The data is also written out to the logs.

# Extensions

Extensions are provided as an attempt to standardize some common features and customizations.

## patching

pg_anon looks for files under extend/patch/[source host fqdn] named either:

- pre_[something].sql - these are executed before anonymization
- post_[something].sql - these are executed after anonymization

## defaults.json

You can define default anonymization configurations which will be applied to the all columns when the state file is generated with --initialize. This will hopefully give you a starting state closer to what you want anonymized.

You can create per-instance defaults by naming them: defaults_[source_host].json. If that file is present, it will use it, otherwise if a defaults.json is present that will be used.

*Note* these are only applied at the initizization phase and can be changed as needed before you upload the state file which will be applied to your target. Think of this as customizable auto-discovery for what you want anonymized in the database.

### options
- faker
  - options: applied at the class level
  - method level configurations: if you want to add arguments to the a method, you can add them as key value pairs nested under the method name.
- columns: applied to all columns except those with type JSON
- json: applied to all columns identified as type JSON

### example defaults.json

```
{
    "faker": {
        "options": ["en_US"],
        "email": {
            "domain": "thisisafakedomain.com"
        }
    },
    "columns": {
            "phone_number": "fake.phone_number()",
            "first_name": "fake.first_name()",
            "last_name": "fake.last_name()",
            "email": "fake.email()",
            "street": "fake.address()",
            "zipcode": "fake.zipcode()",
            "city": "fake.city()",
            "state": "fake.state()",
            "country": "fake.country()",
            "ssn": "fake.ssn()",
            "social_security_number": "fake.ssn()"
    },
    "json": {
        "all_keys": [
            {"phone_number": "faker.phone_number"},
            {"first_name": "faker.first_name"},
            {"last_name": "faker.last_name"},
            {"email": "faker.email"},
            {"street": "fake.address()"},
            {"zipcode": "fake.zipcode()"},
            {"city": "fake.city()"},
            {"state": "fake.state()"},
            {"country": "fake.country()"},
            {"ssn": "fake.ssn()"},
            {"social_security_number": "fake.ssn()"}
        ]
    }
}
```
## custom data types

You can create any custom data types you might want or need by adding them to extend/custom_data_types.py. From there you reference them directly via 'custom.[method name]'. You can also pass in arguments.

### Example custom data type

```
class CustomDataTypes:
    ...
    def phone_number_list(self, args: list = None) -> list:
        # set a default count of 2, but accept a count as an argument
        count = 2
        if args:
            count = args[0]
        return_list = []
        for i in range(count):
            return_list.append(fake.phone_number())
        return return_list
```

### Configuration example

If you just want to reference a custom data type without arguments you can use it similar to how you use faker methods, where you prefix the method with 'custom.'.

```
"anonymize": {
    "type": "custom.phone_number_list"
}
```

You can also pass in arguments to your custom data type through this syntax:


```
{
    "anonymize": {
        "type": "custom",
        "custom": {
            "method": "phone_number_list",
            "args": [3]
        }
    }
}
```

# Workflow

1. Pre-define columns inside extend/defaults.json, patches under extend/patch/[source host] and custom data types in extend/custom_data_types.py to help generate appropriate state if that makes sense for you.
2. run with '--initialize' to create a state definition.
3. verify/update/modify the state file with anonymize options as needed
4. run with '--upload' to update the state file with the anonymize options
5. run with '--dry-run' to make sure the current schema validates against the state file
6. run pg_anon without options to generate an anonymized instance replica based on the source instance.

# configuration examples

The anonymize data blocks are nested under each column, and can be modified to modify apply anonymized data to the fields in the database:

```
{
    "schemas": {
        "public": {
            "tables": {
                "category_updates": {
                    "columns": {
                        "id": {
                            "type": "BIGINT",
                            "anonymize": {}
                        },
                        "category_id": {
                            "type": "UUID",
                            "anonymize": {}
                        },
```

## anonymizer type options

All anonymize blocks support the following overrides.

**ignore_keys**: Ignore this list of keys **at any level**

**persist_values**: Never replace this list of values **at any level**

**unique**: Enforce unique values for fake data. **NOTE: This doesn't work for dictionaries or lists.**

**foreign_key**: Columns with foreign_key set to true are ignored

## anonymize types

**faker**: pganon uses the python [faker](https://faker.readthedocs.io/) module to generate anonymized data. Any default faker method can be use by prefixing the type with 'faker.'. For example, if you want to use the faker method first_name to replace the data of the first name column, you would do something like:

```
"email": {
    "type": "TEXT",
    "anonymize": {
        "type": "faker.email",
        "unique": true
    }
}
```


Aside from the faker methods, pganon supports these types:

**raw**: replace with the literal value

**datetime**: provides faker output: fake.date_time().isoformat()

**custom**: this will return the literal value for a custom data type. 

**json**: anonymizes parts of a JSON object. See the example 'Anonymize a JSON column' below

## Anonymize a string column containing a last name


Any faker method can be use by prefixing the type with 'faker.'

```
"anonymize": {
    "type": "faker.last_name",
}
```
## Anonymize a string column containing a last name **except** for rows with the value 'smith'

```
"anonymize": {
    "type": "faker.last_name",
    "persist_values": ["smith"]
}
```

## Anonymize a JSON column

### JSON Options

**keys**: Replace these specific keys. **prefix with 'root'**

**lists**: Update a list with fake data. **prefix with 'root'**

**all_keys**: Replace all instances of these keys **at any level**

JSON blocks also support these global options:

**custom**: replaces all other logic, see above

**ignore_keys**: Ignore these keys **at any level**

**persist_values**: Never replace these values **at any level**

### Example configuration

```
{
    "anonymize": {
       "type": "json",
       "json": {
           "keys": [
               {"root['phoneNumber']": "faker.phone_number"},
               {"root['firstName']": "faker.first_name"},
               {"root['lastName']": "faker.last_name"}
           ],
           "lists": [
               {
                   "root['agent']['phones']": {
                       "type": "faker.phone_number",
                       "count": 3
                   }
               }
           ],
           "all_keys": [
                {"phone_number": "faker.phone_number"},
                {"first_name": "faker.first_name"},
                {"last_name": "faker.last_name"},
                {"email": "faker.email"},
                {"street": "fake.address()"},
                {"zipcode": "fake.zipcode()"},
                {"city": "fake.city()"},
                {"state": "fake.state()"},
                {"country": "fake.country()"},
                {"ssn": "fake.ssn()"},
                {"social_security_number": "fake.ssn()"}
           ],
           "ignore_keys": [
               "covertAreas"
           ],
           "persist_values": [
               "admin@foo.com",
               "John Smith",
               "Boise"
           ]
       }
    }
}
```

# Thanks

This project was informed and inspired by:
- https://www.greenmask.io/
- https://debezium.io/
- https://github.com/calazans10/pg_anon
- https://postgresql-anonymizer.readthedocs.io/en/stable/
- https://github.com/TantorLabs/pg_anon

If this doesn't fit the bill for you, you may want to check one of those out.

# TODO
- create a pipeline devs can trigger and that can be scheduled
- fix boto logging to json
- monitor for failed pipeline runs
- monitor for long lived dbinspect rds instances on all accounts
- do a restore -> unencrypted snapshot -> restore cycle on db to remove encryption
- support all env vars as config file as well: if config/config_[RDS_SOURCE_ID]_[PGANON_ENVIRONMENT].??
- create a docker image
- maybe try deploying via: https://docs.dbos.dev/