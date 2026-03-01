import os
import sys

# Ensure modules are loaded from parent dir
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app as application
import serverless_wsgi

def handler(event, context):
    return serverless_wsgi.handle_request(application, event, context)
