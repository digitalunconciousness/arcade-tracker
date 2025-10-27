#!/usr/bin/env python3
"""Manually create admin account"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User

def create_admin():
    with app.app_context():
        # Check if any users exist
        existing_users = User.query.count()
        if existing_users > 0:
            print(f"❌ Users already exist ({existing_users} found)")
            users = User.query.all()
            for user in users:
                print(f"   - {user.username} ({user.role})")
            return False
        
        # Get admin details
        print("🔧 Creating admin account...")
        username = input("Enter admin username: ").strip()
        
        if not username:
            print("❌ Username cannot be empty")
            return False
            
        if len(username) < 4:
            print("❌ Username must be at least 4 characters")
            return False
        
        # Get password
        import getpass
        password = getpass.getpass("Enter admin password (min 6 chars): ").strip()
        
        if len(password) < 6:
            print("❌ Password must be at least 6 characters")
            return False
        
        password_confirm = getpass.getpass("Confirm password: ").strip()
        
        if password != password_confirm:
            print("❌ Passwords don't match")
            return False
        
        # Create admin user
        try:
            admin = User(username=username, role='admin')
            admin.set_password(password)
            admin.is_active = True
            
            db.session.add(admin)
            db.session.commit()
            
            print(f"✅ Admin user '{username}' created successfully!")
            print("🌐 You can now login at http://localhost:5000/login")
            return True
            
        except Exception as e:
            print(f"❌ Error creating admin: {e}")
            db.session.rollback()
            return False

if __name__ == '__main__':
    success = create_admin()
    if success:
        print("\n🎉 Setup complete! Start the app with: python app.py")
    else:
        print("\n❌ Setup failed. Please try again.")