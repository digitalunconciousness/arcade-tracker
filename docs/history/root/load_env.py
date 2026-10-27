#!/usr/bin/env python3
"""
Simple environment variable loader for arcade-tracker
Loads variables from .env file if it exists
"""

import os
from pathlib import Path

def load_env():
    """Load environment variables from .env file if it exists"""
    env_path = Path(__file__).parent / '.env'
    
    if env_path.exists():
        print(f"Loading environment variables from {env_path}")
        
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os.environ[key] = value
                    print(f"  Set {key}")
        
        print("Environment variables loaded successfully!")
    else:
        print("No .env file found, using system environment variables only")

if __name__ == '__main__':
    load_env()