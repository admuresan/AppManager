#!/usr/bin/env python3
"""
Script to check if port 6002 is active on the server
"""
import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.utils.app_manager import check_port_status, test_app_port, get_active_ports_and_services

def main():
    port = 6002
    
    print(f"Checking port {port}...")
    print("=" * 50)
    
    # Check detailed status
    status = check_port_status(port)
    
    print(f"\nPort: {status['port']}")
    print(f"Is Listening: {status['is_listening']}")
    print(f"PID: {status['pid'] or 'Not found'}")
    print(f"Service Name: {status['service_name'] or 'Not found'}")
    print(f"Process Name: {status['process_name'] or 'Not found'}")
    print(f"Detection Method: {status['detection_method'] or 'Not detected'}")
    
    # Also check all active ports to see if 6002 is in the list
    print("\n" + "=" * 50)
    print("Checking all active ports...")
    all_ports = get_active_ports_and_services()
    
    port_found = False
    for p in all_ports:
        if p['port'] == port:
            port_found = True
            print(f"\n[OK] Port {port} found in active ports list:")
            print(f"  PID: {p.get('pid') or 'N/A'}")
            print(f"  Service Name: {p.get('service_name') or 'N/A'}")
            print(f"  Process Name: {p.get('process_name') or 'N/A'}")
            break
    
    if not port_found:
        print(f"\n[X] Port {port} NOT found in active ports list")
        print("\nThis could mean:")
        print("  - Port is listening but detection failed")
        print("  - Port is listening on a different interface")
        print("  - Port detection needs improvement")
    
    # Show nearby ports for context
    print("\n" + "=" * 50)
    print("Nearby ports (for context):")
    nearby = [p for p in all_ports if abs(p['port'] - port) <= 10]
    if nearby:
        for p in sorted(nearby, key=lambda x: x['port']):
            marker = " <-- THIS PORT" if p['port'] == port else ""
            print(f"  Port {p['port']}: PID={p.get('pid') or 'N/A'}, Service={p.get('service_name') or 'N/A'}{marker}")
    else:
        print("  No nearby ports found")
    
    print("\n" + "=" * 50)
    if status['is_listening']:
        print(f"[OK] Port {port} IS listening and accessible")
    else:
        print(f"[FAIL] Port {port} is NOT listening or not accessible")

if __name__ == '__main__':
    main()

