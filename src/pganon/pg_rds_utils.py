from sqlalchemy import inspect, MetaData, text, UniqueConstraint, ForeignKeyConstraint
from sqlalchemy.orm import sessionmaker
from typing import Any
import os
import sys
import re
import random
import string
from .loglib import logger, setup_logging
from .retry_utils import RetryUtils
from sqlalchemy.ext.automap import automap_base

retry_utils = RetryUtils()

class PgRdsUtils:
    def __init__(self, engine: Any, source_host: str = None, defaults: dict = None):
        setup_logging()
        self.Session = sessionmaker(bind=engine)
        self.engine = engine
        self.source_host = source_host
        self.defaults = defaults
        self.db_timeout = int(os.getenv('PGANON_DB_TIMEOUT', 30))
        self.db_retries = int(os.getenv('PGANON_DB_RETRIES', 10))
        self.db_backoff_time = int(os.getenv('PGANON_DB_BACKOFF_TIME', 1))
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.extend_path = os.getenv("PGANON_EXTEND_DIR", os.path.join(self.current_dir, '..', '..'))

    def random_pass(self, pass_length=32):
        """Generate a random password."""
        character_set = (
            "abcdefghijklmnopqrstuvwxyz01234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        password = "".join(random.sample(character_set, pass_length))
        return password

    def create_db_admin_permissions(self, user_name: str, db_name: str) -> list:
        permissions = []
        permissions.append(f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {user_name};")
        permissions.append(f"ALTER DATABASE {db_name} OWNER TO {user_name};")
        return permissions

    def create_schema_admin_permissions(self, user_name: str, schema_name: str):
        permissions = []
        permissions.append(f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {schema_name} TO {user_name};")
        permissions.append(f"GRANT USAGE ON SCHEMA {schema_name} TO {user_name};")
        permissions.append(f"GRANT CREATE ON SCHEMA {schema_name} TO {user_name};")
        permissions.append(f"GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {schema_name} TO {user_name};")
        permissions.append(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema_name} GRANT ALL PRIVILEGES ON TABLES TO {user_name};")
        permissions.append(f"ALTER DEFAULT PRIVILEGES IN SCHEMA {schema_name} GRANT ALL ON SEQUENCES TO {user_name};")
        return permissions

    def get_default_faker_value(self, column_name: str, column_type: str) -> dict:
        if not self.defaults:
            return {}
        if column_type.lower() == "json":
            if "json" in self.defaults:
                return {"type": "json","json": self.defaults["json"]}
        else:
            if column_name in self.defaults["columns"]:
                return {"type": self.defaults["columns"][column_name]}
        return {}

    def inspect_db(self, initialize: bool) -> dict:
        # Use the inspector to get all schema names
        try:
            inspector = inspect(self.engine)
        except Exception as e:
            logger.error(f"Connection error while getting schema names: {e}")
            self.engine = retry_utils.get_engine_with_retries(self.engine)
            inspector = inspect(self.engine)
        schemas = inspector.get_schema_names()
        data = {}
        data["schemas"] = {}

        system_schemas = ["information_schema", "pg_catalog", "pg_toast"]
        # Reflect each schema
        for schema in schemas:
            logger.info(f"processing schema {schema}")
            if schema not in system_schemas:
                data["schemas"][schema] = {}
            metadata = MetaData()
            try:
                metadata.reflect(bind=self.engine, schema=schema)
            except Exception as e:
                logger.error(f"Connection error while reflecting schema {schema}: {e}")
                # Attempt to reconnect
                self.engine = retry_utils.get_engine_with_retries(self.engine)
                # Retry reflecting the schema after reconnecting
                metadata.reflect(bind=self.engine, schema=schema)

            Base = automap_base(metadata=metadata)
            Base.prepare()

            # populate tables and columns
            tables = {}
            for table in metadata.tables:
                # logger.info(f"Processing table {table}")
                columns = {}  # Reset columns for each table
                for column in metadata.tables[table].columns:
                    # logger.info(f"Found column {table}.{column.name} of type {column.type}")
                    column_data = {}
                    column_data["type"] = column.type
                    # Check if the column is unique
                    column_is_unique = any(
                        isinstance(constraint, UniqueConstraint) and column.name in constraint.columns
                        for constraint in metadata.tables[table].constraints
                    )
                    # Check if the column is a foreign key
                    column_is_foreign_key = any(
                        isinstance(constraint, ForeignKeyConstraint) and column.name in [fk.name for fk in constraint.columns]
                        for constraint in metadata.tables[table].constraints
                    )
                    if initialize:
                        column_data["anonymize"] = self.get_default_faker_value(str(column.name), str(column.type.__class__.__name__))
                        if column_is_unique:
                            column_data["anonymize"]["unique"] = True
                        if column_is_foreign_key:
                            column_data["anonymize"]["foreign_key"] = True
                        logger.debug(f"column: {column.name}")
                        logger.debug(f"column_data['anonymize']:   {column_data['anonymize']}")
                        logger.debug(f"column_is_unique:           {column_is_unique}")
                        logger.debug(f"column_is_foreign_key:      {column_is_foreign_key}")
                        # print(column_data)
                    #  logger.info(f"Adding column {column.name} to table {table}")
                    columns[column.name] = column_data  # Ensure this is inside the column loop
                tables[table.split(".")[1]] = {"columns": columns}
            if schema not in system_schemas and tables:
                # print(f"adding data to data['schemas'][{schema}]['tables']")
                data["schemas"][schema]["tables"] = tables
            # didn't end up needing this, moved logic above
            # # populate relationships
            # relationships = {}
            # for cls in Base.classes:
            #     relationships[cls.__name__] = {}
            #     all_relationships = {}
            #     for rel in cls.__mapper__.relationships:
            #         # relationships[cls.__name__] = []
            #         foreign_keys = [local.name for local, remote in rel.local_remote_pairs]
            #         relationship_data = {
            #             "foreign_keys": foreign_keys,
            #             "target_column": [remote.name for local, remote in rel.local_remote_pairs],
            #             "target_table": rel.target.name,
            #         }
            #         if relationship_data:
            #             all_relationships[rel.key] = relationship_data
            #     if all_relationships:
            #         relationships[cls.__name__] = all_relationships
            # if schema not in system_schemas and relationships:
            #     data["schemas"][schema]["relationships"] = relationships
        return data

    def execute_patch_sql(self, source_host: str, stage: str) -> None:
        patch_path = os.path.join(self.extend_path, 'patch', f'{source_host}')
        logger.info(f"checking for {stage} stage patches under patch_path: {patch_path}")
        if not os.path.exists(patch_path):
            logger.info(f"Patch path {patch_path} does not exist")
            return
        # read all the sql files in the patch_path
        tmp_files = []
        for file in os.listdir(patch_path):
            if file.startswith(f"{stage}_"):
                if file.endswith('.sql'):
                    logger.debug(f"Adding {stage} patch file {file} for execution")
                    tmp_files.append(file)
        if not tmp_files:
            logger.info(f"No patch files found for stage {stage}")
            return
        try:
            with retry_utils.get_session_with_retries(self.Session()) as session:
                for file in tmp_files:
                    with open(os.path.join(patch_path, file), 'r') as f:
                        logger.info(f"executing {stage} patch file {patch_path}/{file}")
                        sql = f.read()
                        sql_commands = sql.split(';')
                        for command in sql_commands:
                            command = command.strip()
                            if command:  # Ensure the command is not empty
                                logger.debug(f"executing command: {command}")
                                tmp_command = text(command)
                                session.execute(tmp_command)
                session.commit()
        except Exception as e:
            logger.error(f"Error executing patch file {patch_path}/{file}: {e}")
            sys.exit(1)


    def list_databases(self, session: Any):
        """List Databases in an instance."""
        all_dbs = []
        query = text("SELECT datname from pg_database WHERE datistemplate = false")
        result = session.execute(query)
        for row in result:
            if not re.match(r"^(template\d+|postgres|rdsadmin)$", row[0]):
                all_dbs.append(row[0])
        return sorted(all_dbs)

    def list_schemas(self, session: Any):
        """List Schemas in an instance."""
        all_schemas = []
        query = text("select nspname from pg_catalog.pg_namespace where nspowner != 10 order by nspname")
        result = session.execute(query)
        for row in result:
            if not re.match(r"^(pg_.*|information_schema|ddl_artifacts)$", row[0]):
                all_schemas.append(row[0])
        return sorted(all_schemas)

    def update_user_password(self, user_name: str, db_passwd: str = None):
        """Update a user password."""
        if not db_passwd:
            db_passwd = self.random_pass()
        with retry_utils.get_engine_with_retries(self.engine) as session:
            query = text(f"ALTER ROLE {user_name} WITH PASSWORD '{db_passwd}'")
            session.execute(query)

    def create_db_user(self, user_name: str, session: Any, db_passwd: str = None) -> bool:
        """Create an admin user."""
        if not db_passwd:
            db_passwd = self.random_pass()
        try:
            query = text(f"CREATE ROLE {user_name} WITH LOGIN PASSWORD '{db_passwd}';")
            session.execute(query)
            logger.info(f"Created user {user_name}")
            return True
        except Exception as e:
            logger.error(f"Error creating user {user_name}: {e}")
            return False

    def create_new_db_owner(self, user_name: str = None, db_passwd: str = None) -> dict:
        """Update the password of the existing admin user to preserve all permissions."""
        # Get the current user from PGUSER environment variable
        current_user = os.getenv("PGUSER")
        if not current_user:
            logger.error("PGUSER environment variable must be set to update the existing user")
            return {}

        # Generate new password if not provided
        if not db_passwd:
            db_passwd = self.random_pass()

        # If user_name is provided, log a warning but use the current user anyway
        if user_name and user_name != current_user:
            logger.warning(f"Ignoring provided username '{user_name}' - will update password for current user '{current_user}' instead")

        with retry_utils.get_session_with_retries(self.Session()) as session:
            try:
                # Check if current user exists
                user_exists_query = text("SELECT 1 FROM pg_roles WHERE rolname = :user_name")
                result = session.execute(user_exists_query, {"user_name": current_user}).fetchone()
                if not result:
                    logger.error(f"Current user {current_user} does not exist")
                    return {}

                # Update password for the current user
                password_query = text(f"ALTER ROLE {current_user} WITH PASSWORD '{db_passwd}'")
                session.execute(password_query)
                logger.info(f"Updated password for user {current_user}")

                # Get host and database info
                current_db_query = text("SELECT current_database()")
                db_name = session.execute(current_db_query).scalar()
                current_host_query = text("SELECT inet_server_addr() AS server_ip, inet_server_port() AS server_port;")
                host_result = session.execute(current_host_query)
                for row in host_result:
                    host_info = row

                session.commit()
                logger.info(f"Successfully updated password for user {current_user} - all permissions and ownerships preserved")

                return {
                    "host_info": host_info[0],
                    "db_name": db_name,
                    "db_user": current_user,  # Return the current user, not a new name
                    "db_passwd": db_passwd
                }

            except Exception as e:
                logger.error(f"Error updating password for user {current_user}: {e}")
                session.rollback()
                return {}
