#!/usr/bin/env python3
"""
Migration script to add the inventory_request table to the database.
Run this after updating app.py with the InventoryRequest model.
"""

from app import app, db
from sqlalchemy import inspect

def table_exists(table_name):
    """Check if a table exists in the database"""
    inspector = inspect(db.engine)
    return table_name in inspector.get_table_names()

def main():
    with app.app_context():
        print("Checking database schema...")
        
        if table_exists('inventory_request'):
            print("✓ inventory_request table already exists")
        else:
            print("Creating inventory_request table...")
            db.create_all()
            print("✓ inventory_request table created successfully!")
        
        print("\nDatabase migration complete!")

if __name__ == '__main__':
    main()
