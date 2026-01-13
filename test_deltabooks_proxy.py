#!/usr/bin/env python3
"""
Test script to diagnose the deltabooks proxy issue
"""
import requests
import sys

def test_direct_connection():
    """Test direct connection to port 6002"""
    print("=" * 60)
    print("Testing DIRECT connection to localhost:6002")
    print("=" * 60)
    try:
        resp = requests.get('http://localhost:6002/', timeout=5, allow_redirects=True)
        print(f"Status: {resp.status_code}")
        print(f"Headers: {dict(resp.headers)}")
        print(f"Content length: {len(resp.content)}")
        print(f"Content preview (first 500 chars):")
        print(resp.text[:500])
        print()
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_proxy_connection():
    """Test connection through proxy"""
    print("=" * 60)
    print("Testing PROXY connection (through AppManager)")
    print("=" * 60)
    
    # Try both local and remote
    base_urls = [
        'http://localhost:5000',  # Local
        'https://blackgrid.ddns.net',  # Remote
    ]
    
    for base_url in base_urls:
        print(f"\nTesting: {base_url}/deltabooks/")
        try:
            resp = requests.get(f'{base_url}/deltabooks/', timeout=10, allow_redirects=False, verify=False)
            print(f"Status: {resp.status_code}")
            print(f"Headers: {dict(resp.headers)}")
            print(f"Content length: {len(resp.content)}")
            print(f"Content preview (first 1000 chars):")
            print(resp.text[:1000])
            print()
            
            if resp.status_code == 500:
                print("=" * 60)
                print("500 ERROR DETAILS:")
                print("=" * 60)
                print(resp.text)
                print("=" * 60)
        except requests.exceptions.SSLError as e:
            print(f"SSL Error (expected for self-signed cert): {e}")
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

def test_with_headers():
    """Test with specific headers to simulate proxy request"""
    print("=" * 60)
    print("Testing direct connection with PROXY-LIKE headers")
    print("=" * 60)
    try:
        headers = {
            'Host': 'localhost:6002',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Forwarded-Proto': 'http',
        }
        resp = requests.get('http://localhost:6002/', headers=headers, timeout=5, allow_redirects=True)
        print(f"Status: {resp.status_code}")
        print(f"Content preview (first 500 chars):")
        print(resp.text[:500])
        print()
        return resp.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("DeltaBooks Proxy Diagnostic Test")
    print("=" * 60 + "\n")
    
    # Test 1: Direct connection
    direct_ok = test_direct_connection()
    
    # Test 2: Direct with proxy-like headers
    headers_ok = test_with_headers()
    
    # Test 3: Through proxy
    test_proxy_connection()
    
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"Direct connection: {'OK' if direct_ok else 'FAILED'}")
    print(f"With proxy headers: {'OK' if headers_ok else 'FAILED'}")
    print("=" * 60)

