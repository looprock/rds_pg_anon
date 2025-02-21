from .loglib import log_json
import json
import os
from .aws_utils import AWSUtils
from .serializer import default_serializer
from typing import Any
from deepdiff import DeepDiff

aws_utils = AWSUtils()

class StateUtils:
    def __init__(self, engine: Any = None):
        if engine:
            self.engine = engine
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.extend_path = os.getenv("PGANON_EXTEND_DIR", os.path.join(self.current_dir, '..', '..'))

    def read_defaults(self, source_host: str = None) -> dict:
        # Load defaults from defaults.json if it exists
        log_json("searching for defaults files..", level='info')
        defaults_path = os.path.join(self.extend_path, 'defaults.json')
        log_msg = "Using defaults from defaults.json."
        log_json(f"source_host: {source_host}", level='debug')
        if source_host:
            host_defaults_path = os.path.join(self.extend_path, f'defaults_{source_host}.json')
            log_json(f"searching for host defaults file {host_defaults_path}", level='debug')
            if os.path.exists(host_defaults_path):
                defaults_path = host_defaults_path
                log_msg = f"Using host defaults from defaults_{source_host}.json."
        defaults = {}

        if os.path.exists(defaults_path):
            log_json(log_msg, level='info')
            with open(defaults_path, 'r') as f:
                defaults = json.load(f)
        return defaults

    def state_to_dict(self, state_file: str) -> dict:
        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_json(f"Failed to read {state_file}: {e}", level='error')
            exit(1)

    def read_existing_state(self, filename: str, s3_bucket_name: str = None, destination_filename: str = None, local_state: bool = False) -> dict:
        # get the state file from S3
        if s3_bucket_name and not local_state:
            if aws_utils.download_from_s3(s3_bucket_name, filename, destination_filename):
                log_json(f"File {filename} downloaded from S3.")
            else:
                log_json(f"Failed to download {filename} from S3.", level='error')
                exit(1)
        # read it in as existing_data
        error_message = f"S3 state file {filename} not found."
        if local_state:
            log_json(f"Using Local state file {filename}.")
            error_message = f"Local state file {filename} not found."
        if not destination_filename:
            destination_filename = filename
        if os.path.exists(destination_filename):
            existing_data = self.state_to_dict(destination_filename)
        else:
            log_json(error_message, level='error')
            exit(1)
        return existing_data

    def save_or_remove(self, file_name: str, save: bool) -> None:
        if os.path.exists(file_name) and not save:
            os.remove(file_name)

    def process_custom_fields(self, data: dict, check_missing: bool = True) -> dict:
        """Operations against the custom column fields in the data structure."""
        for schema, schema_data in data["schemas"].items():
            # Iterate over tables, which are now a dictionary
            for table_name, table_data in schema_data.get("tables", {}).items():
                # Iterate over columns, which are now a dictionary
                for column_name, column_data in table_data.get("columns", {}).items():
                    # since this is the primary PII related field, we need to check for it
                    if check_missing and "anonymize" not in column_data:
                        log_json(f"Anonymize field missing in column {column_name} of table {table_name}.", level='error')
                        exit(1)
                    # Remove the anonymize field if it exists
                    column_data.pop("anonymize", None)
        return data

    def match_state(self, stored_state: dict, output_file: str, target_engine: Any, initialize: bool, save: bool) -> None:
        work_file = f"{output_file}.work"
        # remove the custom column fields from the stored state
        stored_state = self.process_custom_fields(stored_state)
        # get the current state from the database
        # i'm doing this to ensure the current state is similar to the stored state
        data = target_engine.inspect_db(initialize)
        with open(work_file, 'w') as f:
            json.dump(data, f, indent=4, default=default_serializer)
        current_state = self.read_existing_state(work_file)
        diff = DeepDiff(stored_state, current_state, verbose_level=2)
        if diff:
            print(json.dumps(diff, indent=4))
            log_json("Differences found between existing file and current database state.", level='error')
            log_json(diff, level='error')
            result = False
        else:
            log_json("No differences found between state file and current database state.", level='info')
            result = True
        self.save_or_remove(work_file, save)
        return result
