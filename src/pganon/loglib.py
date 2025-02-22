import logging
import datetime
import json
import os

# Create a logger instance that will be used across the application
logger = logging.getLogger('pganon')
logger.setLevel(logging.INFO)

# Retrieve the log level from an environment variable
log_level = "DEBUG" if os.getenv('PGANON_DEBUG') else "INFO"
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.getenv("PGANON_LOG_DIR"):
    default_log_dir = os.getenv("PGANON_LOG_DIR")
else:
    default_log_dir = os.path.join(current_dir, "..", "..", "logs")

class CustomJsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'level': record.levelname,
            'message': record.getMessage()
        }
        return json.dumps(log_entry)

def setup_logging(log_dir: str = default_log_dir):
    global logger
    
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
    pganon_environment = os.getenv('PGANON_ENVIRONMENT', 'default')
    log_filename = f"{log_dir}/{pganon_environment}-{datetime.datetime.now():%Y-%m-%d_%H-%M}.log"
    fh = logging.FileHandler(log_filename)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    boto3_logger.addHandler(ch)

# Initialize logging with default settings
setup_logging()
