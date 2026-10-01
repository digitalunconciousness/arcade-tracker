#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User

def test_setup():
    print("🔧 Testing authentication setup...")
    
    with app.app_context():
        # Create database tables
        db.create_all()
        print("✅ Database tables created")
        
        # Check if any users exist
        user_count = User.query.count()
        print(f"👥 Users in database: {user_count}")
        
        if user_count == 0:
            print("ℹ️  No users found - setup route will be available")
            print("🌐 Visit http://localhost:5000/setup to create admin user")
        else:
            users = User.query.all()
            print("👤 Existing users:")
            for user in users:
                print(f"   - {user.username} ({user.role})")
        
        print("\n🎮 Authentication System Ready!")
        print("=" * 50)
        print("ROLE PERMISSIONS:")
        print("🔴 Admin:    Full access + user management")
        print("🟡 Manager:  Add/edit games + reports")  
        print("🔵 Operator: Record plays + maintenance")
        print("⚪ ReadOnly: View data only")
        print("=" * 50)

if __name__ == '__main__':
    test_setup()