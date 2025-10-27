# Arcade Tracker Changes Summary

## Completed Changes

### 1. Games Table Updates
✅ Admin and Manager users now have "Add Plays" and "Delete" buttons
✅ Game rows are clickable (navigate to game detail)
✅ Status symbol spacing improved (6px gap)
✅ Position column already not shown (only Location is displayed)
✅ Search bar added with multi-field search (name, manufacturer, genre, location)
✅ Emojis removed from button text, kept in search and status indicators only

### 2. Maintenance Orders Table  
✅ All rows are clickable (navigate to maintenance detail)
✅ Event propagation stopped on action buttons

### 3. Add Game Form
✅ Cabinet photo field removed
✅ Warehouse/floor position fields removed

## To-Do / Notes

### 1. Admin Buttons Issue
The code shows the buttons ARE present for admin users (lines 94-102 in games.html). If you're not seeing them:
- Verify you're logged in as an admin user
- Check browser console for JavaScript errors
- Try clearing browser cache
- The buttons show: "Add Plays", "Edit", "Fix", "Delete"

### 2. Delete Not Working
The delete functionality exists in app.py (line 2425). If it's not working:
- Check CSRF token is present (it's in base.html line 7)
- Check browser console for errors
- The delete uses JavaScript to create and submit a form

### 3. Still Needed - Inventory Request Feature
Need to create:
- InventoryRequest model in app.py
- Request button/form on inventory pages
- Routes to handle requests
- Display of requested items

### 4. Still Needed - Reports Page Overhaul
Current: Multiple buttons for different export types
Needed: Single "Get Reports" dropdown with:
- Revenue reports (revenue for period, top 5, bottom 5)
- Maintenance reports (open orders, closed orders)  
- Inventory reports (low stock, needs/requests)
- Each with CSV export and PDF download options
- Timeframe selection for all report types

## Quick Fixes to Try

### If Delete Not Working:
1. Open browser developer console (F12)
2. Click Delete button
3. Check for errors in console
4. Verify CSRF token is present in page source

### If Admin Buttons Not Showing:
1. Check your user role with: `SELECT username, role FROM user;` in the database
2. Clear browser cache completely
3. Try in incognito/private browsing mode
4. Check the page source - buttons should be in HTML even if styled weird

### To Test Role:
Add this temporarily to games.html after line 4:
```html
<p>DEBUG: Your role is: {{ current_user.role }}</p>
```

## Files Modified
- /home/jackiegreybard/arcade-tracker/templates/games.html
- /home/jackiegreybard/arcade-tracker/templates/maintenance_orders.html
- /home/jackiegreybard/arcade-tracker/templates/add_game.html
- /home/jackiegreybard/arcade-tracker/app.py (games_list function)
