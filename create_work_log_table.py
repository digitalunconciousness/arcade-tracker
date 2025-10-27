#!/usr/bin/env python3
"""
Script to create the WorkLog table and update database schema
Run this after updating the models to create the new work log tracking system
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from datetime import datetime

def create_work_log_table():
    """Create the WorkLog table and update database schema"""
    
    with app.app_context():
        try:
            print("Creating WorkLog table and updating database schema...")
            
            # Create all tables (will create WorkLog table)
            db.create_all()
            
            print("✅ Database schema updated successfully!")
            print("🔧 WorkLog table created - you can now track individual work entries with timestamps")
            
        except Exception as e:
            print(f"❌ Error updating database schema: {e}")
            return False
    
    return True

if __name__ == '__main__':
    if create_work_log_table():
        print("\n🚀 Ready to use the new work logging system!")
        print("📝 Each 'Update' on a maintenance order will now create a new timestamped work entry")
        print("👁️ Use 'View' to see the complete work history timeline")
    else:
        sys.exit(1)