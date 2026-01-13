#!/usr/bin/env python3
"""
Test script to check port 6002 via the API endpoint
"""
import requests
import json
import sys

# Configuration
BASE_URL = "https://blackgrid.ddns.net"  # Change to your server URL
PORT_TO_CHECK = 6002

def test_port_api():
    """Test the new check-port API endpoint"""
    
    # Note: This requires authentication
    # You'll need to login first or use session cookies
    print(f"Testing port {PORT_TO_CHECK} check API endpoint...")
    print(f"Server: {BASE_URL}")
    print("=" * 50)
    print("\nNote: This endpoint requires admin authentication.")
    print("You can test it by:")
    print("1. Logging into the admin dashboard")
    print(f"2. Visiting: {BASE_URL}/admin/api/check-port/{PORT_TO_CHECK}")
    print("\nOr use curl after logging in:")
    print(f"curl -k -b cookies.txt {BASE_URL}/admin/api/check-port/{PORT_TO_CHECK}")
    
    # Try to make the request (will fail without auth, but shows the endpoint)
    try:
        response = requests.get(
            f"{BASE_URL}/admin/api/check-port/{PORT_TO_CHECK}",
            verify=False,
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            print("\n[SUCCESS] API Response:")
            print(json.dumps(data, indent=2))
        elif response.status_code == 401:
            print("\n[INFO] Authentication required (expected)")
            print("Please login to the admin dashboard first")
        else:
            print(f"\n[ERROR] Status code: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"\n[ERROR] Could not connect: {e}")
        print("\nThis is expected if you're not authenticated or the server is not accessible")

if __name__ == '__main__':
    test_port_api()

