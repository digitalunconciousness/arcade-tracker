# 🔐 Authentication System Setup

Your arcade tracker now has a complete authentication system with role-based permissions!

## 🚀 Getting Started

1. **Start the app:**
   ```bash
   cd arcade-tracker
   source venv/bin/activate
   python app.py
   ```

2. **Create your admin account:**
   - Visit: `http://localhost:5000/setup`
   - Create your administrator account
   - You'll be automatically logged in

## 👥 User Roles & Permissions

### 🔴 **Admin** (You)
- ✅ Full access to everything
- 👥 Create new user accounts  
- 🎮 Add/edit/delete games
- 📊 View all reports and export data
- 🔧 Manage maintenance records
- 💿 Record play counts

### 🟡 **Manager** 
- 🎮 Add/edit/delete games
- 📊 View reports and export data  
- 🔧 Manage maintenance records
- 💿 Record play counts
- ❌ Cannot create user accounts

### 🔵 **Operator**
- 💿 Record play counts
- 🔧 Add maintenance records
- 👀 View games and reports
- ❌ Cannot add/edit games
- ❌ Cannot export data

### ⚪ **Read Only**
- 👀 View games, reports, and data only
- ❌ Cannot modify anything

## 🔧 Managing Users

**As an admin, you can:**

1. **Create new users:**
   - Click "👥 Add User" in the navigation
   - Choose their role carefully
   - Give them their login credentials

2. **Share access safely:**
   - Create accounts with appropriate roles
   - Use strong passwords
   - Consider changing the secret key in production

## 🛡️ Security Features

- **Session-based authentication** - users stay logged in
- **Role-based permissions** - each role has specific access
- **Protected routes** - unauthorized users are redirected
- **Password hashing** - passwords are stored securely
- **CSRF protection** - forms are protected against attacks

## 📱 Usage Tips

- **Navigation changes** based on user role
- **User info** shows in top-right corner
- **Logout** button always available
- **Permission errors** show helpful messages

## 🔄 Database Changes

New tables added:
- `user` - stores user accounts and roles

Existing data is preserved - all your games and records are safe!

## 🚨 Important Notes

1. **Change the secret key** for production use (in `app.py`)
2. **The setup route** only works when no users exist
3. **Admin users** can create other admins
4. **Deleted users** lose access immediately

---

**Need help?** The system is designed to be intuitive, but remember:
- Only admins can create users
- Each role builds on the previous (Manager includes Operator permissions)
- Always test with different user roles to verify permissions