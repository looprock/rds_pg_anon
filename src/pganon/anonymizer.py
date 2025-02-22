from .loglib import setup_logging, logger
from faker import Faker
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
import json
import re
import os
import sys
import math
from deepdiff.search import grep
from .serializer import default_serializer
from .state_utils import StateUtils
from .retry_utils import RetryUtils

state_utils = StateUtils()
retry_utils = RetryUtils()
setup_logging()

current_dir = os.path.dirname(os.path.abspath(__file__))
extend_path = os.getenv("PGANON_EXTEND_DIR", os.path.join(current_dir, '..', '..'))
sys.path.append(extend_path)

try:
    from extend.custom_data_types import CustomDataTypes # type: ignore
    custom_data_types = CustomDataTypes()
    logger.info("custom_data_types loaded...")
except ImportError:
    custom_data_types = None
    logger.info("custom_data_types not found...")

# sys.exit(0)

fake = Faker()

class Anonymizer:
    def __init__(self, engine, source_host: str, defaults: dict, dry_run: bool, verbose: bool, debug: bool = False):
        if "faker" in defaults:
            if "options" in defaults["faker"]:
                self.fake = Faker(defaults["faker"]["options"])
            else:
                self.fake = Faker()
        else:
            self.fake = Faker()
        self.defaults = defaults
        self.source_host = source_host
        self.Session = sessionmaker(bind=engine)
        self.dry_run = dry_run
        self.verbose = verbose
        self.debug = debug
        if self.dry_run:
            self.verbose = True
        self.db_max_record_batch = int(os.getenv("PGANON_DB_MAX_RECORD_BATCH", 10000))

    def update_value(self, data, key, value):
        try:
            exec(f"{key} = value")
        except Exception as e:
            logger.error(f"Error updating value key: {key} value: {value} error: {e}")
            sys.exit(1)
        return data

    def replace_all_in_dict(self, anonymize_data: dict, data: dict, search_string: str, new_value: str, exclude_from_all_keys: list = []) -> dict:
        ks = data | grep(search_string)
        logger.debug("exclude_from_all_keys:")
        logger.debug(exclude_from_all_keys)
        if "matched_paths" in ks:
            logger.debug("matched_paths:")
            logger.debug(ks["matched_paths"])
            for path in ks["matched_paths"]:
                skip = False
                # filter out ignore_keys
                if "ignore_keys" in anonymize_data:
                    for ignore_key in anonymize_data["ignore_keys"]:
                        ignore_key_pattern = rf"'{ignore_key}'"
                        if re.search(ignore_key_pattern, path, re.IGNORECASE):
                            logger.debug(f"Ignoring key '{ignore_key}' in path '{path}'")
                            skip = True
                            break
                if skip:
                    continue
                new_path = path.replace("root", "data")
                logger.debug("new_path:")
                logger.debug(new_path)
                if new_path in exclude_from_all_keys:
                    logger.debug(f"--- Ignoring explicitly configured path '{new_path}'")
                    continue
                else:
                    logger.debug(f"not in exclude_from_all_keys: {new_path}")
                logger.debug(f"*** Continuing to process {new_path}...")
                pattern = rf"'{search_string}'"
                if re.search(pattern, new_path, re.IGNORECASE):
                    message = f"Key match found for '{search_string}' in {new_path}"
                    logger.debug(message)
                    logger.debug(message)
                    data = self.update_value(data, new_path, new_value)
                else:
                    logger.debug(f"No match found for '{search_string}' in {new_path}")
        if "matched_values" in ks:
            for path in ks["matched_values"]:
                logger.debug(f"path: {path}")
                new_path = path.replace("root", "data")
                logger.debug(f"new_path: {new_path}")
                kv = eval(new_path)
                # filter out persist_values
                if "persist_values" in anonymize_data:
                    for persist_value in anonymize_data["persist_values"]:
                        if kv == persist_value:
                            logger.debug(f"Ignoring persist_value '{persist_value}' in {new_path}")
                            continue
                # make sure we exactly match the search string
                if kv == search_string:
                    message = f"Value match found for '{search_string}' in {new_path}"
                    logger.debug(message)
                    logger.debug(message)
                    data = self.update_value(data, new_path, new_value)
                else:
                    logger.debug(f"No match found for '{search_string}' in {new_path}")
        return data

    def return_fake_data_list(self, count: int, data_type: str) -> list:
        return_list = []
        for i in range(count):
            val_type = {"type": data_type}
            return_list.append(self.generate_fake_data(val_type))
        return return_list

    def path_exists(self, data, path):
        # Remove the initial 'data' and split the path into keys
        # Adjust the split to handle the format correctly
        keys = path.strip("data[]").split("']['")
        keys[0] = keys[0].strip("'")  # Remove leading quote from the first key
        keys[-1] = keys[-1].strip("'")  # Remove trailing quote from the last key

        current_level = data

        for key in keys:
            if key in current_level:
                current_level = current_level[key]
            else:
                return False
        return True

    def json_fake_data(self, data: dict, anonymize_data: dict) -> dict:
        json_data = anonymize_data["json"]
        logger.debug("starting data:")
        logger.debug(data)

        exclude_from_all_keys = []

        # if there are specific keys, do this:
        if "keys" in json_data:
            for key in json_data["keys"]:
                for k, v in key.items():
                    logger.debug(f"start processing keys key: {k}")
                    new_path = k.replace("root", "data")
                    if self.path_exists(data, new_path):
                        val_type = {"type": v}
                        data = self.update_value(data, new_path, self.generate_fake_data(val_type))
                        exclude_from_all_keys.append(new_path)
                    else:
                        logger.debug(f"path {new_path} does not exist in data")

        if "lists" in json_data:
            for replace_list in json_data["lists"]:
                for k, v in replace_list.items():
                    new_path = k.replace("root", "data")
                    if self.path_exists(data, new_path):
                        data = self.update_value(data, new_path, self.return_fake_data_list(v["count"], v["type"]))
                        exclude_from_all_keys.append(new_path)
                    else:
                        logger.debug(f"path {new_path} does not exist in data")

        # if there are items in all_keys, do this:
        if "all_keys" in json_data:
            for key in json_data["all_keys"]:
                for k, v in key.items():
                    logger.debug(f"start processing all_keys key: {k}")
                    val_type = {"type": v}
                    data = self.replace_all_in_dict(val_type, data, k, self.generate_fake_data(val_type), exclude_from_all_keys)

        logger.debug("processed data:")
        logger.debug(data)
        return data

    # Function to generate fake data based on column type
    def generate_fake_data(self, anonymize_data, data=None, existing_values=set()):
        faker_type = anonymize_data["type"].split(".")
        if faker_type[0] == "faker":
            faker_config = {}
            method_name = faker_type[1]
            faker_method = getattr(fake, method_name)
            if method_name in self.defaults["faker"]:
                logger.debug(f"found faker method {method_name} in defaults")
                faker_config = self.defaults["faker"].get(method_name, {})
            if faker_method:
                if faker_config:
                    return faker_method(**faker_config)
                else:
                    return faker_method()
            else:
                logger.error(f"Faker method {method_name} not found")
                exit(1)
        
        if faker_type[0] == "custom":
            if not custom_data_types:
                logger.error("custom data used, but custom_data_types not found")
                exit(1)
            logger.debug(anonymize_data)
            # we will look for args in the custom data definition if it exists
            custom_method_args = []
            if faker_type[1]:
                custom_method_name = faker_type[1]
            elif "custom" in anonymize_data:
                custom_method_name = anonymize_data["custom"]["method"]
                # Check if there are any arguments
                if "args" in anonymize_data["custom"]:
                    custom_method_args = anonymize_data["custom"]["args"]
            else:
                logger.error("Unable to identify custom method")
                exit(1)
            logger.debug(f"custom_method_name: {custom_method_name}")
            logger.debug(f"custom_method_args: {custom_method_args}")
            custom_method = getattr(custom_data_types, custom_method_name)
            if custom_method:
                if custom_method_args:
                    return custom_method(*custom_method_args)
                else:
                    return custom_method()
            else:
                logger.error(f"Custom method {custom_method_name} not found")
                exit(1)

        if faker_type[0] == "raw":
            return faker_type[1]

        if anonymize_data["type"] == "datetime":
            return fake.date_time().isoformat()

        if anonymize_data["type"] == "json":
            if not anonymize_data["json"]:
                logger.error("No data provided for type: json")
                exit(1)
            return self.json_fake_data(data, anonymize_data)
        return None

    def fetch_existing_values(self, session, schema_name, table_name, column_name):
        logger.debug(f"fetching existing values for {schema_name}.{table_name}.{column_name}")
        # Check the column type before fetching values
        column_type_stmt = text(f"SELECT data_type FROM information_schema.columns WHERE table_schema = '{schema_name}' AND table_name = '{table_name}' AND column_name = '{column_name}'")
        column_type_result = session.execute(column_type_stmt).fetchone()
        
        if column_type_result and column_type_result[0] in ['character varying', 'text']:  # Include 'text' type
            select_stmt = text(f"SELECT DISTINCT {column_name} FROM {schema_name}.{table_name}")
            result = session.execute(select_stmt)
            return [row[0] for row in result if isinstance(row[0], str)]
        else:
            logger.debug(f"Column {column_name} in {schema_name}.{table_name} is not a string type.")
            return []

    def update_data(self, session, schema_name, table_name, column_name, updates):
        if updates:
            try:
                update_stmt = text(f"""
                    UPDATE {schema_name}.{table_name}
                    SET {column_name} = :fake_data
                    WHERE id = :id
                """)
                if not self.dry_run:
                    session.execute(update_stmt, updates)
                session.commit()
            except Exception as e:
                logger.error(f"Error updating data: {e}")
                logger.debug(updates)
                return False

    def anonymize_data(self, json_data: dict) -> None:
        # Ensure json_data is a dictionary
        if isinstance(json_data, str):
            try:
                json_data = json.loads(json_data)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON data: {e}")
                return
        with retry_utils.get_session_with_retries(self.Session()) as session:
            # Traverse the JSON and update database columns with anonymize = True
            all_fake_data = {}
            for schema_name, schema in json_data["schemas"].items():
                if "tables" in schema:
                    for table_name, table in schema["tables"].items():
                        if "columns" in table:
                            for column_name, column in table["columns"].items():
                                column_fake_data = f"{schema_name}_{table_name}_{column_name}"
                                anonymize_data = column.get("anonymize")
                                if anonymize_data:
                                    if "type" not in anonymize_data:
                                        logger.debug(f"type not found in anonymize_data for {schema_name}.{table_name}.{column_name}, skipping...")
                                        break
                                    # don't process data with a foreign key constraint
                                    if "foreign_key" in anonymize_data and anonymize_data["foreign_key"]:
                                        logger.info(f"column identified as a foreign_key in anonymize_data for {schema_name}.{table_name}.{column_name}, skipping...")
                                        break
                                    count_stmt = text(f"SELECT COUNT(*) FROM {schema_name}.{table_name}")
                                    total_updates = session.execute(count_stmt).scalar()  # Get total count of records
                                    total_batches = math.ceil(total_updates / self.db_max_record_batch)
                                    # it is expensive to index all the existing values, so we only do it if unique is true
                                    if "unique" in anonymize_data and anonymize_data["unique"] and anonymize_data["type"] != "json":
                                            logger.info(f"found unique constraint for column {schema_name}.{table_name}.{column_name}.")
                                            existing_values = self.fetch_existing_values(session, schema_name, table_name, column_name)
                                            all_fake_data[column_fake_data] = set(existing_values)
                                    logger.info(f"anonymizing: {schema_name}.{table_name}.{column_name}")
                                    # Fetch all rows from the table
                                    if self.debug:
                                        select_hostinfo = text("SELECT inet_server_addr() AS server_ip, inet_server_port() AS server_port;")
                                        host_result = session.execute(select_hostinfo)
                                        for row in host_result:
                                            logger.debug(f"hostinfo: {row}")
                                    select_stmt = text(f"SELECT id,{column_name} FROM {schema_name}.{table_name}")
                                    logger.debug(f"select_stmt: {select_stmt}")
                                    result = session.execute(select_stmt)
                                    updates = []
                                    updates_count = 1
                                    for row in result:
                                        if row[1]:
                                            if self.verbose:
                                                logger.info(f"*** Original data for {schema_name}.{table_name}.{column_name} id: {row.id}:")
                                                logger.info(json.dumps(row, indent=4, default=default_serializer))
                                            # original_data = row[1]
                                            if anonymize_data["type"] == "json":
                                                if getattr(row, column_name):
                                                    # sometimes we get non-json data in the column, so we need to convert it to json
                                                    column_data = getattr(row, column_name)
                                                    if not isinstance(column_data, dict):
                                                        logger.debug(f"Converting non-json data to json for {schema_name}.{table_name}.{column_name} id: {row.id}")
                                                        column_data = {"original_data": column_data}
                                                    fake_data = self.generate_fake_data(anonymize_data, column_data)
                                            else:
                                                fake_data = self.generate_fake_data(anonymize_data)
                                                if "unique" in anonymize_data and anonymize_data["unique"]:
                                                    attempts = 0
                                                    max_attempts = 10  # Set a limit for attempts
                                                    while fake_data in all_fake_data[column_fake_data] and attempts < max_attempts:
                                                        fake_data = self.generate_fake_data(anonymize_data)
                                                        attempts += 1

                                                    if attempts == max_attempts:
                                                        logger.error(f"Failed to generate unique fake_data for {column_fake_data} after {max_attempts} attempts.")
                                                        exit(1)
                                                    else:
                                                        all_fake_data[column_fake_data].add(fake_data)
                                            if self.verbose:
                                                original_fake_data = fake_data
                                            # Serialize fake_data if it's a dictionary or list
                                            if isinstance(fake_data, (dict, list)):
                                                fake_data = json.dumps(fake_data, default=default_serializer)
                                            # Collect updates in a list
                                            if self.debug:
                                                print(f"{schema_name}.{table_name}.{column_name} id: {row.id} fake_data (type: {str(type(fake_data))}): {fake_data}")
                                            updates.append({
                                                'id': row.id,
                                                'fake_data': fake_data
                                            })
                                            if self.verbose:
                                                if fake_data:
                                                    if anonymize_data["type"] == "json":
                                                        logger.info("Fake data:")
                                                        logger.info(json.dumps(original_fake_data, indent=4, default=default_serializer))
                                                    else:
                                                        logger.info("Fake data:")
                                                        logger.info(original_fake_data)
                                            if len(updates) >= self.db_max_record_batch:
                                                logger.info(f"Update {updates_count} of {total_batches}: updating {str(len(updates))} {schema_name}.{table_name}.{column_name} records...")
                                                self.update_data(session, schema_name, table_name, column_name, updates)
                                                updates = []
                                                updates_count += 1
                                    # Execute all remaining updates in a batch
                                    if updates:
                                        logger.info(f"Updating remaining {str(len(updates))} {schema_name}.{table_name}.{column_name} records...")
                                        self.update_data(session, schema_name, table_name, column_name, updates)
        return True
