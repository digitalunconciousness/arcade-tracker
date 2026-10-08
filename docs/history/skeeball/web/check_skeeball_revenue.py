#!/usr/bin/env python3
"""
Test script for skeeball revenue integration.

This script tests the revenue tracking system by simulating coin insertions
and verifying that they are properly recorded in the database.
"""

import requests
import json
from datetime import date

# Configuration
BASE_URL = "http://localhost:5000"
USERNAME = "admin"  # Change to your admin username
PASSWORD = "admin"  # Change to your admin password

def test_skeeball_revenue_integration():
    """Test the skeeball revenue integration."""
    
    print("=" * 60)
    print("SKEEBALL REVENUE INTEGRATION TEST")
    print("=" * 60)
    
    # Create a session to maintain login
    session = requests.Session()
    
    # Step 1: Login
    print("\n1. Logging in...")
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "csrf_token": ""  # Will need to handle CSRF if enabled
    }
    
    # For testing, we'll use the API endpoints which should work with session auth
    # First, get the login page to establish a session
    resp = session.get(f"{BASE_URL}/login")
    if resp.status_code != 200:
        print(f"❌ Failed to access login page: {resp.status_code}")
        return False
    
    # Try to login (simplified - may need CSRF handling)
    print("   Note: You should already be logged in via browser for API testing")
    
    # Step 2: Register the skeeball lane as a game
    print("\n2. Registering skeeball lane as a game...")
    register_data = {
        "name": "Skeeball Lane 1",
        "manufacturer": "Skeeball Inc.",
        "location": "Floor",
        "floor_position": "Front Row",
        "coins_per_play": 0.25
    }
    
    try:
        resp = session.post(
            f"{BASE_URL}/skeeball/api/lanes/lane_1/register-game",
            json=register_data
        )
        if resp.status_code in [200, 201]:
            result = resp.json()
            print(f"   ✅ {result['message']}")
            print(f"   Game ID: {result['game_id']}, Name: {result['game_name']}")
            game_id = result['game_id']
        else:
            print(f"   ❌ Failed to register: {resp.status_code}")
            print(f"   Response: {resp.text}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Step 3: Check current revenue data
    print("\n3. Checking current revenue data...")
    try:
        resp = session.get(f"{BASE_URL}/skeeball/api/lanes/lane_1/revenue")
        if resp.status_code == 200:
            revenue_data = resp.json()
            print(f"   Daily coins: {revenue_data['daily_coins']}")
            print(f"   Last sync: {revenue_data['last_sync']}")
        else:
            print(f"   ⚠️  Could not fetch revenue data: {resp.status_code}")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    # Step 4: Simulate coin insertions
    print("\n4. Simulating coin insertions (inserting 5 coins)...")
    for i in range(5):
        try:
            resp = session.post(
                f"{BASE_URL}/skeeball/api/simulator/insert-coin",
                json={"lane_id": "lane_1"}
            )
            if resp.status_code == 200:
                print(f"   ✅ Coin {i+1} inserted")
            else:
                print(f"   ❌ Failed to insert coin {i+1}: {resp.status_code}")
        except Exception as e:
            print(f"   ❌ Error inserting coin {i+1}: {e}")
    
    # Step 5: Check revenue data again
    print("\n5. Checking revenue data after coin insertion...")
    try:
        resp = session.get(f"{BASE_URL}/skeeball/api/lanes/lane_1/revenue")
        if resp.status_code == 200:
            revenue_data = resp.json()
            print(f"   ✅ Daily coins: {revenue_data['daily_coins']}")
            print(f"   Expected: 5 coins")
            if revenue_data['daily_coins'] == 5:
                print("   ✅ Coin tracking working correctly!")
            else:
                print("   ⚠️  Coin count mismatch")
        else:
            print(f"   ❌ Could not fetch revenue data: {resp.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Step 6: Sync revenue to database
    print("\n6. Syncing revenue to database...")
    try:
        resp = session.post(f"{BASE_URL}/skeeball/api/lanes/lane_1/sync-revenue")
        if resp.status_code == 200:
            result = resp.json()
            print(f"   ✅ {result['message']}")
            print(f"   Game: {result['game_name']}")
            print(f"   Plays: {result['plays']}")
            print(f"   Revenue: ${result['revenue']:.2f}")
            print(f"   Date: {result['date']}")
        else:
            print(f"   ❌ Failed to sync: {resp.status_code}")
            print(f"   Response: {resp.text}")
            return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Step 7: Verify revenue was reset
    print("\n7. Verifying daily counter was reset...")
    try:
        resp = session.get(f"{BASE_URL}/skeeball/api/lanes/lane_1/revenue")
        if resp.status_code == 200:
            revenue_data = resp.json()
            print(f"   Daily coins: {revenue_data['daily_coins']}")
            if revenue_data['daily_coins'] == 0:
                print("   ✅ Counter reset successfully!")
            else:
                print("   ⚠️  Counter not reset")
        else:
            print(f"   ⚠️  Could not verify reset: {resp.status_code}")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Check the Games list in the web UI - you should see 'Skeeball Lane 1'")
    print("2. Check the game's play records - you should see today's entry")
    print("3. The revenue scheduler will auto-sync at midnight each night")
    print("4. Use /skeeball/api/revenue/sync-all to manually sync all lanes")
    print("\n")
    
    return True


if __name__ == "__main__":
    print("\n⚠️  IMPORTANT: Make sure you're logged into the web interface")
    print("   in your browser before running this test, or it may fail.")
    print("\n   This test uses session-based authentication.\n")
    
    input("Press Enter to continue...")
    
    try:
        test_skeeball_revenue_integration()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
