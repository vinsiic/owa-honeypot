import os
import gunicorn
from dotenv import load_dotenv

load_dotenv()

# Return fake Server header in response
gunicorn.SERVER = 'Microsoft-IIS/' + os.getenv("IIS_VERSION", "10.0")

# Params
HOST = os.getenv("HOST", "0.0.0.0")
PORT = os.getenv("PORT", "1337")
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
WORKERS = int(os.getenv("WORKERS", "4"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# Gunicorn binding configuration: "host:port"
bind = f"{HOST}:{PORT}"

# IMPORTANT: Enable code reloading if DEBUG is True. Turn DEBUG to False in production!!!!!!
reload = DEBUG

# Number of worker processes for handling requests
workers = WORKERS

# Logging configuration
loglevel = LOG_LEVEL
accesslog = '-'  # Log access logs to stdout
errorlog = '-'   # Log error logs to stderr
