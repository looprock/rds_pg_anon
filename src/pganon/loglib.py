import logging
import datetime
import json
import os
global log_level

# Retrieve the log level from an environment variable
log_level = "DEBUG" if os.getenv('DBINSPECT_DEBUG') else "INFO"

# Configure logging with the specified log level
logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format='%(message)s')
def log_json(message: str, level: str = 'info'):
    log_entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'level': level.upper(),
        'message': message
    }
    if level == 'info':
        logging.info(json.dumps(log_entry))
    elif level == 'error':
        logging.error(json.dumps(log_entry))
    elif level == 'warning':
        logging.warning(json.dumps(log_entry))
    elif level == 'debug':
        logging.debug(json.dumps(log_entry))