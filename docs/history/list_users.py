#!/usr/bin/env python3
"""Quick script to list all user accounts"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User
from datetime import datetime

def list_users():
    with app.app_context():
        users = User.query.order_by(User.created_at.desc()).all()
        
        if not users:
            print("❌ No users found")
            return
        
        print(f"👥 Found {len(users)} user(s):")
        print("=" * 60)
        
        for user in users:
            status = "✅ Active" if user.is_active else "❌ Disabled"
            created = user.created_at.strftime('%Y-%m-%d %H:%M')
            role_emoji = {
                'admin': '🔴',
                'manager': '🟡', 
                'operator': '🔵',
                'readonly': '⚪'
            }.get(user.role, '❓')
            
            print(f"{role_emoji} {user.username}")
            print(f"   Role: {user.role.title()}")
            print(f"   Status: {status}")
            print(f"   Created: {created}")
            print("-" * 40)

if __name__ == '__main__':
    list_users()