from sqlalchemy import create_engine
from typing import Any
import os
import sys
from .loglib import log_json
import time

class RetryUtils:
    def __init__(self):
        self.db_timeout = int(os.getenv('PGANON_DB_TIMEOUT', 30))
        self.db_retries = int(os.getenv('PGANON_DB_RETRIES', 10))
        self.db_backoff_time = int(os.getenv('PGANON_DB_BACKOFF_TIME', 1))

    def get_engine_with_retries(self, engine: Any):
        # Attempt to create the engine with retries and backoff
        retries = self.db_retries
        backoff_time = self.db_backoff_time  # Start with 1 second backoff
        for attempt in range(retries):
            try:
                retry_engine = create_engine(
                    str(engine.url),
                    connect_args=engine.connect_args  # Set the connection timeout
                )
                return retry_engine
            except Exception as e:
                log_json(f"Attempt {attempt + 1} to connect to the database failed: {e}", level='error')
                if attempt < retries - 1:
                    log_json(f"Waiting for {backoff_time} seconds before retrying...", level='info')
                    time.sleep(backoff_time)  # Wait before retrying
                    backoff_time *= 2  # Double the backoff time for the next attempt
                else:
                    sys.exit(1)  # Reraise the exception if the last attempt fails

    def get_session_with_retries(self, session: Any):
        retries = self.db_retries
        backoff_time = self.db_backoff_time
        for attempt in range(retries):
            try:
                return session  # Return a new session
            except Exception as e:
                log_json(f"Attempt {attempt + 1} to create session failed: {e}", level='error')
                if attempt < retries - 1:
                    log_json(f"Waiting for {backoff_time} seconds before retrying...", level='info')
                    time.sleep(backoff_time)
                    backoff_time *= 2  # Double the backoff time
                else:
                    sys.exit(1)  # Exit if all attempts fail