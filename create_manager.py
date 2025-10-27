#!/usr/bin/env python3
"""Create a test manager account"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User

def create_manager():
    with app.app_context():
        # Check if manager already exists
        existing_manager = User.query.filter_by(username='test_manager').first()
        if existing_manager:
            print(f"❌ User 'test_manager' already exists with role: {existing_manager.role}")
            return False
        
        # Create manager user
        try:
            manager = User(username='test_manager', role='manager')
            manager.set_password('manager123')  # Simple password for testing
            manager.is_active = True
            
            db.session.add(manager)
            db.session.commit()
            
            print("✅ Manager user created successfully!")
            print("📋 Login Details:")
            print("   Username: test_manager")
            print("   Password: manager123")
            print("   Role: Manager")
            print("🌐 Login at: http://localhost:5000/login")
            return True
            
        except Exception as e:
            print(f"❌ Error creating manager: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = create_manager()
    
    # Show all users
    if success:
        print("\n👥 All Users:")
        print("=" * 40)
        with app.app_context():
            users = User.query.all()
            for user in users:
                role_emoji = {'admin': '🔴', 'manager': '🟡', 'operator': '🔵', 'readonly': '⚪'}.get(user.role, '❓')
                print(f"{role_emoji} {user.username} ({user.role})")