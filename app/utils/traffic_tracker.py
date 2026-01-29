"""
Traffic tracking utility for AppManager.
Tracks visits, unique visitors, geography, and per-app statistics.

IMPORTANT: Read `instructions/architecture` before making changes.
"""
import json
import os
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import requests
from threading import Lock

# Thread-safe lock for file operations
_traffic_lock = Lock()

def _get_traffic_file_path(instance_path):
    """Get the path to the traffic data file"""
    traffic_dir = Path(instance_path) / 'data'
    traffic_dir.mkdir(exist_ok=True)
    return traffic_dir / 'traffic_stats.json'

def _get_admin_ips_file_path(instance_path):
    """Get the path to the admin IPs file"""
    traffic_dir = Path(instance_path) / 'data'
    traffic_dir.mkdir(exist_ok=True)
    return traffic_dir / 'admin_ips.json'

def _load_admin_ips(instance_path):
    """Load list of admin IP addresses"""
    admin_ips_file = _get_admin_ips_file_path(instance_path)
    if admin_ips_file.exists():
        try:
            with open(admin_ips_file, 'r') as f:
                data = json.load(f)
                # Return set of IPs, with timestamp tracking
                return set(data.get('ips', []))
        except:
            pass
    return set()

def _save_admin_ips(instance_path, admin_ips):
    """Save list of admin IP addresses"""
    admin_ips_file = _get_admin_ips_file_path(instance_path)
    try:
        with open(admin_ips_file, 'w') as f:
            json.dump({'ips': list(admin_ips), 'updated': datetime.now().isoformat()}, f, indent=2)
    except Exception as e:
        import logging
        logging.error(f"Error saving admin IPs: {e}")

def add_admin_ip(instance_path, ip_address):
    """Add an IP address to the admin IPs list"""
    if not ip_address or _is_local_ip(ip_address):
        return  # Don't add local IPs
    with _traffic_lock:
        admin_ips = _load_admin_ips(instance_path)
        admin_ips.add(ip_address)
        _save_admin_ips(instance_path, admin_ips)

def _get_admin_logins_file_path(instance_path):
    """Get the path to the admin logins file"""
    traffic_dir = Path(instance_path) / 'data'
    traffic_dir.mkdir(exist_ok=True)
    return traffic_dir / 'admin_logins.json'

def _load_admin_logins(instance_path):
    """Load admin login history"""
    logins_file = _get_admin_logins_file_path(instance_path)
    if logins_file.exists():
        try:
            with open(logins_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return {'logins': []}

def _save_admin_logins(instance_path, data):
    """Save admin login history"""
    logins_file = _get_admin_logins_file_path(instance_path)
    try:
        with open(logins_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        import logging
        logging.error(f"Error saving admin logins: {e}")

def track_admin_login(instance_path, ip_address):
    """Track an admin login"""
    if not ip_address:
        return
    
    with _traffic_lock:
        data = _load_admin_logins(instance_path)
        
        # Get geographic info
        geo_info = _get_geo_info(ip_address)
        
        # Current timestamp
        timestamp = datetime.now().isoformat()
        
        # Add login record
        login_record = {
            'ip': ip_address,
            'timestamp': timestamp,
            'country': geo_info['country'],
            'country_code': geo_info['country_code'],
            'city': geo_info['city'],
            'region': geo_info['region']
        }
        
        data['logins'].append(login_record)
        
        # Keep only last 1000 logins to prevent file from growing too large
        if len(data['logins']) > 1000:
            data['logins'] = data['logins'][-1000:]
        
        _save_admin_logins(instance_path, data)

def get_admin_login_stats(instance_path, current_ip=None):
    """Get admin login statistics grouped by IP"""
    with _traffic_lock:
        data = _load_admin_logins(instance_path)
        
        # Group logins by IP
        ip_stats = {}
        for login in data.get('logins', []):
            ip = login.get('ip')
            if not ip:
                continue
            
            if ip not in ip_stats:
                ip_stats[ip] = {
                    'ip': ip,
                    'login_count': 0,
                    'last_login': None,
                    'country': login.get('country', 'Unknown'),
                    'city': login.get('city', 'Unknown'),
                    'region': login.get('region', 'Unknown'),
                    'is_current': False
                }
            
            ip_stats[ip]['login_count'] += 1
            
            # Update last login if this is more recent
            login_time = login.get('timestamp')
            if login_time:
                if ip_stats[ip]['last_login'] is None or login_time > ip_stats[ip]['last_login']:
                    ip_stats[ip]['last_login'] = login_time
        
        # Mark current IP
        if current_ip:
            if current_ip in ip_stats:
                ip_stats[current_ip]['is_current'] = True
        
        # Convert to list and sort by last login (most recent first)
        stats_list = list(ip_stats.values())
        stats_list.sort(key=lambda x: x['last_login'] or '', reverse=True)
        
        return stats_list

def _get_visitor_id(ip_address, user_agent):
    """Generate a unique visitor ID from IP and User-Agent"""
    # Create a hash of IP + User-Agent for visitor tracking
    # This is not perfect but provides reasonable uniqueness
    combined = f"{ip_address}:{user_agent}"
    return hashlib.md5(combined.encode()).hexdigest()

def _get_geo_info(ip_address):
    """Get geographic information for an IP address"""
    # Use a free geolocation API (ip-api.com free tier)
    # Fallback to basic info if API fails
    try:
        # Skip localhost/private IPs
        if ip_address in ('127.0.0.1', 'localhost', '::1') or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return {
                'country': 'Local',
                'country_code': 'LOC',
                'city': 'Local',
                'region': 'Local'
            }
        
        # Use ip-api.com free tier (no API key needed, rate limited)
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,region', timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'XX'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown')
                }
    except Exception:
        pass
    
    # Fallback
    return {
        'country': 'Unknown',
        'country_code': 'XX',
        'city': 'Unknown',
        'region': 'Unknown'
    }

def _load_traffic_data(instance_path):
    """Load traffic data from file"""
    traffic_file = _get_traffic_file_path(instance_path)
    
    if not traffic_file.exists():
        return {
            'visits': [],
            'visitors': {},
            'apps': defaultdict(lambda: {
                'visits': 0,
                'unique_visitors': set(),
                'countries': defaultdict(int),
                'referrers': defaultdict(int),
                'last_visit': None
            }),
            'total_visits': 0,
            'total_unique_visitors': 0,
            'start_date': datetime.now().isoformat()
        }
    
    try:
        with open(traffic_file, 'r') as f:
            data = json.load(f)
            
            # Convert sets back from lists (JSON doesn't support sets)
            # Also ensure apps dict uses defaultdict
            apps_dict = defaultdict(lambda: {
                'visits': 0,
                'unique_visitors': set(),
                'countries': defaultdict(int),
                'referrers': defaultdict(int),
                'last_visit': None
            })
            for app_name, app_data in data.get('apps', {}).items():
                app_dict = {
                    'visits': app_data.get('visits', 0),
                    'unique_visitors': set(app_data.get('unique_visitors', [])),
                    'countries': defaultdict(int, app_data.get('countries', {})),
                    'referrers': defaultdict(int, app_data.get('referrers', {})),
                    'last_visit': app_data.get('last_visit')
                }
                apps_dict[app_name] = app_dict
            data['apps'] = apps_dict
            
            # Convert visits list timestamps back to datetime strings
            return data
    except Exception:
        # If file is corrupted, return empty data
        return {
            'visits': [],
            'visitors': {},
            'apps': defaultdict(lambda: {
                'visits': 0,
                'unique_visitors': set(),
                'countries': defaultdict(int),
                'referrers': defaultdict(int),
                'last_visit': None
            }),
            'total_visits': 0,
            'total_unique_visitors': 0,
            'start_date': datetime.now().isoformat()
        }

def _save_traffic_data(instance_path, data):
    """Save traffic data to file"""
    traffic_file = _get_traffic_file_path(instance_path)
    
    # Prepare data for JSON serialization
    json_data = data.copy()
    
    # Convert sets to lists for JSON
    json_data['apps'] = {}
    for app_name, app_data in data['apps'].items():
        app_json = app_data.copy()
        if 'unique_visitors' in app_json:
            app_json['unique_visitors'] = list(app_json['unique_visitors'])
        if 'countries' in app_json:
            app_json['countries'] = dict(app_json['countries'])
        if 'referrers' in app_json:
            app_json['referrers'] = dict(app_json['referrers'])
        json_data['apps'][app_name] = app_json
    
    try:
        with open(traffic_file, 'w') as f:
            json.dump(json_data, f, indent=2)
    except Exception as e:
        # Log error but don't fail the request
        import logging
        logging.error(f"Error saving traffic data: {e}")

def track_visit(instance_path, app_name, ip_address, user_agent, path='/', referrer=None):
    """Track a visit to an app"""
    with _traffic_lock:
        data = _load_traffic_data(instance_path)
        
        # Generate visitor ID
        visitor_id = _get_visitor_id(ip_address, user_agent)
        
        # Get geographic info
        geo_info = _get_geo_info(ip_address)
        
        # Current timestamp
        now = datetime.now()
        timestamp = now.isoformat()
        
        # Normalize referrer (remove query params, normalize domain)
        normalized_referrer = 'Direct'  # Default to 'Direct' for direct traffic
        if referrer:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(referrer)
                # Only track external referrers (not from same domain)
                if parsed.netloc:
                    # Store just the domain for privacy and simplicity
                    normalized_referrer = parsed.netloc.replace('www.', '')
                elif not parsed.netloc and parsed.path:
                    # Internal referrer (no domain, just path)
                    normalized_referrer = 'Internal'
            except:
                normalized_referrer = referrer[:100] if referrer else 'Direct'  # Truncate if too long
        
        # Track visit
        visit_record = {
            'timestamp': timestamp,
            'app': app_name,
            'visitor_id': visitor_id,
            'ip': ip_address,
            'path': path,
            'country': geo_info['country'],
            'country_code': geo_info['country_code'],
            'city': geo_info['city'],
            'referrer': normalized_referrer
        }
        
        data['visits'].append(visit_record)
        
        # Track unique visitors
        if visitor_id not in data['visitors']:
            data['visitors'][visitor_id] = {
                'first_seen': timestamp,
                'last_seen': timestamp,
                'ip': ip_address,
                'country': geo_info['country'],
                'country_code': geo_info['country_code']
            }
            data['total_unique_visitors'] = len(data['visitors'])
        else:
            data['visitors'][visitor_id]['last_seen'] = timestamp
        
        # Track per-app statistics
        if app_name not in data['apps']:
            data['apps'][app_name] = {
                'visits': 0,
                'unique_visitors': set(),
                'countries': defaultdict(int),
                'referrers': defaultdict(int),
                'last_visit': None
            }
        
        app_data = data['apps'][app_name]
        app_data['visits'] += 1
        app_data['unique_visitors'].add(visitor_id)
        app_data['countries'][geo_info['country']] += 1
        if normalized_referrer:
            app_data['referrers'][normalized_referrer] += 1
        app_data['last_visit'] = timestamp
        
        # Update totals
        data['total_visits'] = len(data['visits'])
        
        # Keep only last 30 days of visit records to prevent file from growing too large
        cutoff_date = now - timedelta(days=30)
        data['visits'] = [
            v for v in data['visits']
            if datetime.fromisoformat(v['timestamp']) > cutoff_date
        ]
        
        # Clean up old visitors (not seen in 30 days)
        cutoff_iso = cutoff_date.isoformat()
        visitors_to_remove = [
            vid for vid, visitor in data['visitors'].items()
            if visitor['last_seen'] < cutoff_iso
        ]
        for vid in visitors_to_remove:
            del data['visitors'][vid]
        data['total_unique_visitors'] = len(data['visitors'])
        
        # Save data
        _save_traffic_data(instance_path, data)

def _is_local_ip(ip_address):
    """Check if an IP address is from the local computer"""
    if not ip_address:
        return False
    ip_lower = ip_address.lower()
    # Check for localhost
    if ip_lower in ('127.0.0.1', 'localhost', '::1', '0.0.0.0'):
        return True
    # Check for private IP ranges
    if ip_lower.startswith('192.168.') or ip_lower.startswith('10.') or ip_lower.startswith('172.16.'):
        return True
    # Check for localhost IPv6
    if ip_lower.startswith('::ffff:127.0.0.1'):
        return True
    return False

def get_traffic_stats(instance_path, days=30, include_local=True):
    """Get traffic statistics for the last N days
    
    Args:
        instance_path: Path to instance folder
        days: Number of days to include
        include_local: If False, exclude visits from local IP addresses
    """
    with _traffic_lock:
        data = _load_traffic_data(instance_path)
        
        # Filter visits by date range
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_visits = [
            v for v in data['visits']
            if datetime.fromisoformat(v['timestamp']) > cutoff_date
        ]
        
        # Filter out local visits and admin IPs if requested
        if not include_local:
            admin_ips = _load_admin_ips(instance_path)
            recent_visits = [
                v for v in recent_visits
                if not _is_local_ip(v.get('ip')) and v.get('ip') not in admin_ips
            ]
        
        # Calculate unique visitors from filtered visits
        filtered_visitor_ids = set(v['visitor_id'] for v in recent_visits)
        
        # Calculate statistics
        stats = {
            'total_visits': len(recent_visits),
            'total_unique_visitors': len(filtered_visitor_ids),
            'period_days': days,
            'start_date': data.get('start_date', datetime.now().isoformat()),
            'apps': {}
        }
        
        # Helper function to extract base app name (removing :port and https :port suffixes)
        def get_base_app_name(app_name):
            """Extract base app name, removing port suffixes like ' :port' and ' https :port'"""
            # Remove patterns like " :1234" or " https :1234" at the end
            # Match: space, optional "https", space, colon, digits
            base_name = re.sub(r'\s+(?:https\s+)?:\d+$', '', app_name)
            return base_name
        
        # Group app names by base name for aggregation
        # First pass: collect all base app names and their variants
        base_app_groups = defaultdict(list)
        for app_name in data['apps'].keys():
            base_name = get_base_app_name(app_name)
            base_app_groups[base_name].append(app_name)
        
        # Per-app statistics (aggregated by base app name)
        for base_app_name, app_variants in base_app_groups.items():
            # Collect all visits for all variants of this app
            all_app_visits = []
            all_app_visitor_ids = set()
            latest_visit = None
            
            for app_name in app_variants:
                # Filter visits for this app variant in the period
                app_visits = [v for v in recent_visits if v['app'] == app_name]
                all_app_visits.extend(app_visits)
                
                # Collect unique visitors
                for visit in app_visits:
                    all_app_visitor_ids.add(visit['visitor_id'])
                
                # Track latest visit across all variants
                app_data = data['apps'].get(app_name, {})
                variant_last_visit = app_data.get('last_visit')
                if variant_last_visit:
                    if latest_visit is None or variant_last_visit > latest_visit:
                        latest_visit = variant_last_visit
            
            # Get country breakdown for all variants combined
            country_counts = defaultdict(int)
            referrer_counts = defaultdict(int)
            for visit in all_app_visits:
                country_counts[visit['country']] += 1
                # Track referrer (will be 'Direct' if no referrer was present)
                referrer = visit.get('referrer', 'Direct')
                referrer_counts[referrer] += 1
            
            stats['apps'][base_app_name] = {
                'visits': len(all_app_visits),
                'unique_visitors': len(all_app_visitor_ids),
                'countries': dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)),
                'referrers': dict(sorted(referrer_counts.items(), key=lambda x: x[1], reverse=True)),
                'top_referrers': dict(sorted(referrer_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
                'last_visit': latest_visit,
                'top_countries': dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            }
        
        # Overall country breakdown
        overall_countries = defaultdict(int)
        overall_referrers = defaultdict(int)
        for visit in recent_visits:
            overall_countries[visit['country']] += 1
            # Track referrer (will be 'Direct' if no referrer was present)
            referrer = visit.get('referrer', 'Direct')
            overall_referrers[referrer] += 1
        stats['countries'] = dict(sorted(overall_countries.items(), key=lambda x: x[1], reverse=True))
        stats['top_countries'] = dict(sorted(overall_countries.items(), key=lambda x: x[1], reverse=True)[:10])
        stats['referrers'] = dict(sorted(overall_referrers.items(), key=lambda x: x[1], reverse=True))
        stats['top_referrers'] = dict(sorted(overall_referrers.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Daily visit counts for chart
        daily_counts = defaultdict(int)
        for visit in recent_visits:
            visit_date = datetime.fromisoformat(visit['timestamp']).date()
            daily_counts[visit_date.isoformat()] += 1
        
        # Fill in missing days with 0
        start_date = datetime.now().date() - timedelta(days=days-1)
        daily_visits = []
        for i in range(days):
            date = start_date + timedelta(days=i)
            date_str = date.isoformat()
            daily_visits.append({
                'date': date_str,
                'visits': daily_counts.get(date_str, 0)
            })
        
        stats['daily_visits'] = daily_visits
        
        # Hourly distribution (for today)
        today = datetime.now().date()
        today_visits = [v for v in recent_visits if datetime.fromisoformat(v['timestamp']).date() == today]
        hourly_counts = defaultdict(int)
        for visit in today_visits:
            hour = datetime.fromisoformat(visit['timestamp']).hour
            hourly_counts[hour] += 1
        
        hourly_distribution = []
        for hour in range(24):
            hourly_distribution.append({
                'hour': hour,
                'visits': hourly_counts.get(hour, 0)
            })
        stats['hourly_distribution'] = hourly_distribution
        
        return stats

