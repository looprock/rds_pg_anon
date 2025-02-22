import logging
import datetime
import json
import os
import sys
# Create a logger instance that will be used across the application
logger = logging.getLogger('pganon')
logger.setLevel(logging.INFO)

# Retrieve the log level from an environment variable
log_level = "DEBUG" if os.getenv('PGANON_DEBUG') else "INFO"

class CustomJsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'level': record.levelname,
            'message': record.getMessage()
        }
        return json.dumps(log_entry)

def setup_logging():
    global logger
    log_dir = os.getenv("PGANON_LOG_PATH")
    log_filename = os.getenv("PGANON_LOG_FILE")

    if not log_dir or not log_filename:
        logger.error("PGANON_LOG_PATH and PGANON_LOG_FILE must be set")
        sys.exit(1)

    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Set log level
    logger.setLevel(logging.DEBUG if log_level == 'DEBUG' else logging.INFO)
    formatter = CustomJsonFormatter()

    # Also set up boto3 logger
    boto3_logger = logging.getLogger('boto3')
    boto3_logger.setLevel(logging.INFO)
    if log_level == 'DEBUG':
        boto3_logger.setLevel(logging.DEBUG)

    # Create a console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    if log_level == 'DEBUG':
        ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    boto3_logger.addHandler(ch)

    if os.getenv('PGANON_DISABLE_LOCAL_LOGGING'):
        return

    # Create log directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Define log filename
    full_log_filename = os.path.join(log_dir, log_filename)
    fh = logging.FileHandler(full_log_filename)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    boto3_logger.addHandler(ch)

# Initialize logging with default settings
setup_logging()
