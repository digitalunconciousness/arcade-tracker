#!/usr/bin/env python3
"""
Simple test script to verify key functionality works after implementing new features.
"""
import requests
import json
import sys

def test_endpoint(url, description, expected_status=200):
    """Test a single endpoint"""
    try:
        print(f"Testing {description}...")
        response = requests.get(url, timeout=5)
        if response.status_code == expected_status:
            print(f"✅ {description} - OK ({response.status_code})")
            return True
        else:
            print(f"❌ {description} - FAILED ({response.status_code})")
            return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False

def main():
    """Run basic functionality tests"""
    base_url = "http://127.0.0.1:5000"
    
    print("🧪 Testing Arcade Tracker Application")
    print("=" * 50)
    
    tests_passed = 0
    total_tests = 0
    
    # Test endpoints that should be accessible without login (redirects expected)
    endpoints_to_test = [
        ("/" , "Homepage redirect", 302),
        ("/login", "Login page", 200),  
        ("/setup", "Setup page (if no users)", [200, 302]),  # Could be either
    ]
    
    for endpoint, description, expected in endpoints_to_test:
        total_tests += 1
        url = base_url + endpoint
        
        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            if isinstance(expected, list):
                success = response.status_code in expected
            else:
                success = response.status_code == expected
                
            if success:
                print(f"✅ {description} - OK ({response.status_code})")
                tests_passed += 1
            else:
                print(f"❌ {description} - FAILED ({response.status_code}, expected {expected})")
                
        except Exception as e:
            print(f"❌ {description} - ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"Tests completed: {tests_passed}/{total_tests} passed")
    
    if tests_passed == total_tests:
        print("🎉 All basic tests passed! Application appears to be working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the application logs.")
        return 1

if __name__ == "__main__":
    sys.exit(main())