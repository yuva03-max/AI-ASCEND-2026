import os
import sys

# Add the parent directory to sys.path so we can import from the root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the initialized Flask app (with routes registered) from main
from main import app

# For Vercel, 'app' needs to be available
# Vercel looks for 'app', 'application', or 'handler' by default
