from flask import Flask, request, jsonify, redirect
import requests
import secrets
import hashlib
import base64
import urllib.parse
import webbrowser
import time
import warnings
import json
import os
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for development
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

app = Flask(__name__)

# Use Railway's persistent volume or fallback to current directory
DATA_DIR = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '/data')
# Create the data directory if it doesn't exist
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR)
        print(f"Created data directory at: {DATA_DIR}")
    except Exception as e:
        print(f"Failed to create data directory: {e}")
        # Fallback to current directory if volume not available
        DATA_DIR = '.'
# Define file paths
TOKENS_FILE = os.path.join(DATA_DIR, 'soho_tokens.json')
LAST_BOOKING_FILE = os.path.join(DATA_DIR, 'last_booking.json')

# Log the paths being used
print(f"DATA_DIR: {DATA_DIR}")
print(f"TOKENS_FILE: {TOKENS_FILE}")
print(f"LAST_BOOKING_FILE: {LAST_BOOKING_FILE}")
print(f"DATA_DIR exists: {os.path.exists(DATA_DIR)}")
print(f"DATA_DIR is writable: {os.access(DATA_DIR, os.W_OK)}")


# OAuth configuration
CLIENT_ID = "e7f9c1e1584911fcdd1d9ceb9f1ffac8e175e1ba639e5bcbc58ca76b9ea084f2"
REDIRECT_URI = "com.sohohouse.houseseven://authcallback"
IDENTITY_BASE_URL = "https://identity.sohohouse.com"


# Store PKCE parameters temporarily
oauth_sessions = {}

def generate_code_verifier():
    """Generate a code verifier for PKCE"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    """Generate code challenge from verifier"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

@app.route("/start-auth", methods=['GET'])
def start_auth():
    """Start the OAuth flow - opens browser for manual login"""
    
    # Generate PKCE parameters
    session_id = secrets.token_urlsafe(16)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(32)
    
    # Store session data
    oauth_sessions[session_id] = {
        'code_verifier': code_verifier,
        'state': state,
        'created_at': time.time()
    }
    
    # Build authorization URL
    auth_params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'all',
        'response_type': 'code',
        'state': state,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge
    }
    
    auth_url = f"{IDENTITY_BASE_URL}/authorize?" + urllib.parse.urlencode(auth_params)
    
    # Open browser
    webbrowser.open(auth_url)
    
    return jsonify({
        "message": "Browser opened for login",
        "session_id": session_id,
        "instructions": [
            "1. Complete the login in your browser (including reCAPTCHA)",
            "2. After login, you'll be redirected to a URL starting with 'com.sohohouse.houseseven://'",
            "3. Copy the ENTIRE redirect URL",
            "4. Call POST /complete-auth with session_id and redirect_url"
        ],
        "authorization_url": auth_url
    })

# Update the complete_auth endpoint to use the helper functions
@app.route("/complete-auth", methods=['POST'])
def complete_auth():
    """Complete the OAuth flow with the redirect URL from manual login"""
    
    data = request.json
    session_id = data.get('session_id')
    redirect_url = data.get('redirect_url')
    
    if not session_id or not redirect_url:
        return jsonify({"error": "Missing session_id or redirect_url"}), 400
    
    # Get session data
    session_data = oauth_sessions.get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid or expired session"}), 400
    
    # Parse the redirect URL to get the authorization code
    try:
        parsed_url = urllib.parse.urlparse(redirect_url)
        params = urllib.parse.parse_qs(parsed_url.query)
        auth_code = params.get('code', [None])[0]
        state = params.get('state', [None])[0]
        
        if not auth_code:
            return jsonify({"error": "No authorization code in redirect URL"}), 400
        
        # Debug information
        print(f"Expected state: {session_data['state']}")
        print(f"Received state: {state}")
        
        # Verify state matches
        if state != session_data['state']:
            return jsonify({
                "error": "State mismatch - possible CSRF attack",
                "debug": {
                    "expected_state": session_data['state'],
                    "received_state": state,
                    "hint": "Make sure you're using the redirect URL from the same login attempt"
                }
            }), 400
        
    except Exception as e:
        return jsonify({"error": f"Failed to parse redirect URL: {str(e)}"}), 400
    
    # Exchange code for token
    token_data = {
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": auth_code,
        "code_verifier": session_data['code_verifier']
    }
    
    headers = {
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    print(f"Exchanging code for token...")
    print(f"Code: {auth_code[:20]}...")
    
    response = requests.post(
        f"{IDENTITY_BASE_URL}/oauth/token",
        json=token_data,
        headers=headers,
        verify=False  # Disable SSL verification for development
    )
    
    # Clean up session
    del oauth_sessions[session_id]
    
    if response.status_code == 200:
        token_response = response.json()
        
        # Save tokens automatically
        token_save_data = {
            'access_token': token_response.get('access_token'),
            'refresh_token': token_response.get('refresh_token'),
            'created_at': token_response.get('created_at', int(time.time())),
            'expires_in': token_response.get('expires_in', 7200),
            'token_type': token_response.get('token_type')
        }
        
        saved = save_json_file(TOKENS_FILE, token_save_data)
        
        return jsonify({
            "success": True,
            "access_token": token_response.get('access_token'),
            "token_type": token_response.get("token_type"),
            "expires_in": token_response.get("expires_in"),
            "refresh_token": token_response.get("refresh_token"),
            "created_at": token_response.get("created_at"),
            "tokens_saved": saved,
            "save_path": TOKENS_FILE if saved else None,
            "next_step": f"Use the access_token to make API calls or test with GET /test-token/{token_response.get('access_token')}"
        })
    else:
        return jsonify({
            "error": "Failed to exchange code for token",
            "status": response.status_code,
            "response": response.text
        }), 500


@app.route("/book-poolside/<token>", methods=['POST'])
def book_poolside(token):
    """Book a poolside table using the authenticated token"""
    
    data = request.json
    venue_id = data.get('venue_id', 'NY_POOLSIDE')  # Default to NY poolside
    party_size = data.get('party_size', 2)
    phone_country_code = data.get('phone_country_code', 'US')  # Changed default to 'US'
    phone_number = data.get('phone_number', '7709255248')
    date_time = data.get('date_time')
    if not date_time:
        # Calculate 48 hours from now at 1:30 PM
        booking_date = datetime.now() + timedelta(days=2)
        date_time = booking_date.strftime('%Y-%m-%d') + 'T13:30'
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    # Step 1: Lock the table
    lock_data = {
        "data": {
            "type": "table_locks",
            "attributes": {
                "party_size": party_size,
                "extra_attribute": "default",
                "date_time": date_time
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                }
            }
        }
    }
    
    print(f"Locking table at {venue_id} for {date_time}...")
    print(f"Lock request: {json.dumps(lock_data, indent=2)}")
    
    lock_response = requests.post(
        "https://api.production.sohohousedigital.com/tables/locks?include=venue,restaurant",
        json=lock_data,
        headers=headers,
        verify=False
    )
    
    print(f"Lock response status: {lock_response.status_code}")
    print(f"Lock response: {lock_response.text[:500]}")
    
    if lock_response.status_code not in [200, 201]:
        return jsonify({
            "error": "Failed to lock table",
            "status": lock_response.status_code,
            "response": lock_response.text
        }), 500
    
    lock_response_data = lock_response.json()
    lock_info = lock_response_data.get('data', {})
    lock_id = lock_info.get('id')
    lock_token = lock_info.get('attributes', {}).get('token')
    
    print(f"Lock successful! Lock ID: {lock_id}")
    print(f"Lock token: {lock_token[:50]}...")
    
    # Step 2: Create the booking
    booking_data = {
        "data": {
            "type": "table_bookings",
            "attributes": {
                "date_time": date_time,
                "party_size": party_size,
                "phone": {
                    "country_code": phone_country_code,
                    "number": phone_number
                },
                "guest_notes": "",
                "terms_consent": True,
                "guest_consent": True
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                },
                "table_lock": {
                    "data": {
                        "type": "table_locks",
                        "id": lock_id
                    }
                }
            }
        }
    }
    
    print(f"Creating booking...")
    print(f"Booking request: {json.dumps(booking_data, indent=2)}")
    
    booking_response = requests.post(
        "https://api.production.sohohousedigital.com/tables/table_bookings?include=venue,restaurant",
        json=booking_data,
        headers=headers,
        verify=False
    )
    
    print(f"Booking response status: {booking_response.status_code}")
    print(f"Booking response: {booking_response.text[:500]}")
    
    if booking_response.status_code in [200, 201]:
        booking_result = booking_response.json()
        booking_info = booking_result.get('data', {})
        
        return jsonify({
            "success": True,
            "booking_id": booking_info.get('id'),
            "booking_details": {
                "venue": venue_id,
                "date_time": date_time,
                "party_size": party_size,
                "status": booking_info.get('attributes', {}).get('state'),
                "lock_expires_at": lock_info.get('attributes', {}).get('expires_at')
            },
            "raw_response": booking_result
        })
    else:
        return jsonify({
            "error": "Failed to create booking",
            "status": booking_response.status_code,
            "response": booking_response.text
        }), 500

@app.route("/check-poolside-availability/<token>", methods=['GET'])
def check_poolside_availability(token):
    """Check available poolside tables at different venues"""
    
    venue_id = request.args.get('venue_id', 'NY_POOLSIDE')
    date_time = request.args.get('date_time')
    party_size = request.args.get('party_size', 2, type=int)
    
    # If no date_time provided, default to 48 hours from now at 1:30 PM
    if not date_time:
        booking_date = datetime.now() + timedelta(days=2)
        date_time = booking_date.strftime('%Y-%m-%d') + 'T13:30'
    party_size = request.args.get('party_size', 2, type=int)
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    availability_url = (
        f"https://api.production.sohohousedigital.com/tables/availabilities"
        f"?filter[restaurant_id]={venue_id}"
        f"&filter[start_date_time]={date_time}"
        f"&filter[party_size]={party_size}"
        f"&filter[search_alternatives]=true"
        f"&include=venue,restaurant"
    )
    
    response = requests.get(availability_url, headers=headers, verify=False)
    
    if response.status_code == 200:
        data = response.json()
        
        # Debug: print full response
        print(f"Full availability response: {json.dumps(data, indent=2)}")
        
        available_data = data.get('data', [])
        
        # Check if we're getting restaurant options or time slots
        if available_data and isinstance(available_data[0], dict):
            first_item = available_data[0]
            
            # If it has a type of 'restaurants' or similar, these are venue options
            if first_item.get('type') == 'restaurants' or not first_item.get('attributes', {}).get('start_date_time'):
                # These are restaurant options, not time slots
                formatted_venues = []
                for item in available_data:
                    formatted_venues.append({
                        "restaurant_id": item.get('id'),
                        "name": item.get('attributes', {}).get('name', item.get('id'))
                    })
                
                return jsonify({
                    "type": "restaurant_options",
                    "message": "These are available restaurants. Use one of these restaurant_ids to get actual time slots.",
                    "available_restaurants": formatted_venues,
                    "search_params": {
                        "date": date_time,
                        "party_size": party_size
                    }
                })
            else:
                # These should be actual time slots
                formatted_slots = []
                for slot in available_data:
                    attrs = slot.get('attributes', {})
                    formatted_slots.append({
                        "id": slot.get('id'),
                        "time": attrs.get('start_date_time') or attrs.get('date_time'),
                        "duration": attrs.get('duration'),
                        "table_type": attrs.get('table_type'),
                        "area": attrs.get('area')
                    })
                
                return jsonify({
                    "type": "time_slots",
                    "venue": venue_id,
                    "date": date_time,
                    "party_size": party_size,
                    "available_slots": formatted_slots,
                    "total_available": len(formatted_slots)
                })
        
        return jsonify({
            "error": "Unexpected response format",
            "raw_data": data
        })
    else:
        return jsonify({
            "error": "Failed to check availability",
            "status": response.status_code,
            "response": response.text
        }), response.status_code

@app.route("/pool-venues", methods=['GET'])
def get_pool_venues():
    """Get list of pool venue IDs from the captured data"""
    
    pool_venues = {
        "new_york": {
            "pool": "NY_POOL",
            "poolside_restaurant": "NY_POOLSIDE",
            "premium_pool": "NY_PREM_POOL"
        },
        "miami": {
            "pool": "MIAMI_POOL",
            "cabanas": "MIAMI_CABANAS"
        },
        "white_city": {
            "pool": "WC_POOL"
        },
        "shoreditch": {
            "pool": "SHP_POOL"
        },
        "barcelona": {
            "pool": "BCL_POOL"
        },
        "dumbo": {
            "pool": "DUMBO_POOL",
            "premium_pool": "DUMBO_PREM_POOL"
        },
        "chicago": {
            "pool": "CHIGO_POOL"
        },
        "los_angeles": {
            "pool_deck": "DTLA_POOL_DECK"
        }
    }
    
    return jsonify(pool_venues)

@app.route("/test-token/<token>", methods=['GET'])
def test_token(token):
    """Test if the Bearer token works by fetching account info"""
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': '*/*',
        'Content-Type': 'application/vnd.api+json',
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Time-Zone': 'America/New_York',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)',
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'no-cache'
    }
    
    url = "https://api.production.sohohousedigital.com/profiles/accounts/me?include=profile,membership,features,favorite_venues,favorite_content_categories,profile.mutual_connection_requests,profile.mutual_connections,local_house,latest_attendance&updated_after=0001-01-01T00:00:00Z"
    
    print(f"Testing token: {token[:20]}...")
    print(f"URL: {url}")
    print(f"Headers: {headers}")
    
    response = requests.get(url, headers=headers, verify=False)
    
    print(f"Response Status: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"Response Body: {response.text[:500]}")
    
    if response.status_code == 200:
        account_data = response.json()
        
        # Extract useful info
        data = account_data.get('data', {})
        attributes = data.get('attributes', {})
        profile = attributes.get('profile', {})
        membership = attributes.get('membership', {})
        
        return jsonify({
            "success": True,
            "user_info": {
                "name": f"{profile.get('first_name', '')} {profile.get('last_name', '')}",
                "email": attributes.get('email'),
                "membership_type": membership.get('name'),
                "membership_status": membership.get('status'),
                "id": data.get('id')
            },
            "raw_data": account_data
        })
    else:
        return jsonify({
            "success": False,
            "status": response.status_code,
            "error": response.text,
            "debug": {
                "url": url,
                "token_preview": token[:20] + "...",
                "response_headers": dict(response.headers)
            }
        })

# Cleanup old sessions periodically
@app.before_request
def cleanup_sessions():
    current_time = time.time()
    expired = [sid for sid, data in oauth_sessions.items() 
               if current_time - data['created_at'] > 600]  # 10 min timeout
    for sid in expired:
        del oauth_sessions[sid]

@app.route("/test-lock/<token>", methods=['POST'])
def test_lock(token):
    """Test locking a table with different parameters"""
    
    data = request.json
    venue_id = data.get('venue_id', 'NY_POOLSIDE')
    date_time = data.get('date_time')
    party_size = data.get('party_size', 1)
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    # Try different lock request formats
    attempts = []
    
    # Attempt 1: Basic format
    lock_data_1 = {
        "data": {
            "type": "table_locks",
            "attributes": {
                "party_size": party_size,
                "extra_attribute": "default",
                "date_time": date_time
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                }
            }
        }
    }
    
    response = requests.post(
        "https://api.production.sohohousedigital.com/tables/locks?include=venue,restaurant",
        json=lock_data_1,
        headers=headers,
        verify=False
    )
    
    attempts.append({
        "attempt": 1,
        "description": "Basic format with extra_attribute",
        "status": response.status_code,
        "response": response.text[:200]
    })
    
    if response.status_code in [200, 201]:
        return jsonify({
            "success": True,
            "working_format": 1,
            "lock_response": response.json()
        })
    
    # Attempt 2: Without extra_attribute
    lock_data_2 = {
        "data": {
            "type": "table_locks",
            "attributes": {
                "party_size": party_size,
                "date_time": date_time
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                }
            }
        }
    }
    
    response = requests.post(
        "https://api.production.sohohousedigital.com/tables/locks?include=venue,restaurant",
        json=lock_data_2,
        headers=headers,
        verify=False
    )
    
    attempts.append({
        "attempt": 2,
        "description": "Without extra_attribute",
        "status": response.status_code,
        "response": response.text[:200]
    })
    
    if response.status_code in [200, 201]:
        return jsonify({
            "success": True,
            "working_format": 2,
            "lock_response": response.json()
        })
    
    # Attempt 3: With venue relationship too
    lock_data_3 = {
        "data": {
            "type": "table_locks",
            "attributes": {
                "party_size": party_size,
                "extra_attribute": "default",
                "date_time": date_time
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                },
                "venue": {
                    "data": {
                        "type": "venues",
                        "id": venue_id
                    }
                }
            }
        }
    }
    
    response = requests.post(
        "https://api.production.sohohousedigital.com/tables/locks?include=venue,restaurant",
        json=lock_data_3,
        headers=headers,
        verify=False
    )
    
    attempts.append({
        "attempt": 3,
        "description": "With venue relationship",
        "status": response.status_code,
        "response": response.text[:200]
    })
    
    if response.status_code in [200, 201]:
        return jsonify({
            "success": True,
            "working_format": 3,
            "lock_response": response.json()
        })
    
    return jsonify({
        "success": False,
        "message": "All lock attempts failed",
        "attempts": attempts,
        "test_params": {
            "venue_id": venue_id,
            "date_time": date_time,
            "party_size": party_size
        }
    })

@app.route("/poolside-slots/<token>", methods=['GET'])
def get_poolside_slots(token):
    """Get available poolside time slots"""
    
    venue_id = request.args.get('venue_id', 'NY_POOLSIDE')
    date = request.args.get('date', '2025-06-03')
    
    # Poolside bookings are typically in 3-hour slots from 8am to 8pm
    time_slots = [
        f"{date}T08:00",
        f"{date}T08:15", 
        f"{date}T08:30",
        f"{date}T08:45",
        f"{date}T09:00",
        f"{date}T09:15",
        f"{date}T09:30",
        f"{date}T09:45",
        f"{date}T10:00",
        f"{date}T10:15",
        f"{date}T10:30",
        f"{date}T10:45",
        f"{date}T11:00",
        f"{date}T11:15",
        f"{date}T11:30",
        f"{date}T11:45",
        f"{date}T12:00",
        f"{date}T12:15",
        f"{date}T12:30",
        f"{date}T12:45",
        f"{date}T13:00",
        f"{date}T13:15",
        f"{date}T13:30",
        f"{date}T13:45",
        f"{date}T14:00",
        f"{date}T14:15",
        f"{date}T14:30",
        f"{date}T14:45",
        f"{date}T15:00",
        f"{date}T15:15",
        f"{date}T15:30",
        f"{date}T15:45",
        f"{date}T16:00",
        f"{date}T16:15",
        f"{date}T16:30",
        f"{date}T16:45",
        f"{date}T17:00",
        f"{date}T17:15",
        f"{date}T17:30",
        f"{date}T17:45",
        f"{date}T18:00",
        f"{date}T18:15",
        f"{date}T18:30",
        f"{date}T18:45",
        f"{date}T19:00",
        f"{date}T19:15",
        f"{date}T19:30",
        f"{date}T19:45",
        f"{date}T20:00"
    ]
    
    return jsonify({
        "venue": venue_id,
        "date": date,
        "available_slots": time_slots,
        "note": "Poolside bookings are 3-hour slots. Choose any start time from 8am to 8pm.",
        "booking_instruction": "Use POST /book-poolside/{token} with venue_id, date_time, and party_size"
    })

def save_json_file(filepath, data):
    """Helper function to save JSON with error handling"""
    try:
        # Ensure directory exists
        directory = os.path.dirname(filepath)
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        # Write to temporary file first
        temp_file = filepath + '.tmp'
        with open(temp_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        # Rename to final file (atomic operation)
        os.rename(temp_file, filepath)
        
        print(f"Successfully saved file: {filepath}")
        return True
    except Exception as e:
        print(f"Error saving file {filepath}: {e}")
        return False

def load_json_file(filepath):
    """Helper function to load JSON with error handling"""
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        print(f"Successfully loaded file: {filepath}")
        return data
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return None
    except Exception as e:
        print(f"Error loading file {filepath}: {e}")
        return None

# Add a debug endpoint to check volume status
@app.route("/debug-volume", methods=['GET'])
def debug_volume():
    """Debug endpoint to check volume configuration"""
    debug_info = {
        "RAILWAY_VOLUME_MOUNT_PATH": os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', 'Not set'),
        "DATA_DIR": DATA_DIR,
        "DATA_DIR_exists": os.path.exists(DATA_DIR),
        "DATA_DIR_writable": os.access(DATA_DIR, os.W_OK) if os.path.exists(DATA_DIR) else False,
        "TOKENS_FILE": TOKENS_FILE,
        "TOKENS_FILE_exists": os.path.exists(TOKENS_FILE),
        "LAST_BOOKING_FILE": LAST_BOOKING_FILE,
        "LAST_BOOKING_FILE_exists": os.path.exists(LAST_BOOKING_FILE),
        "cwd": os.getcwd(),
        "environment_variables": {k: v for k, v in os.environ.items() if 'RAILWAY' in k}
    }
    
    # Try to list files in DATA_DIR
    try:
        debug_info["files_in_data_dir"] = os.listdir(DATA_DIR)
    except Exception as e:
        debug_info["files_in_data_dir"] = f"Error: {str(e)}"
    
    # Try to write a test file
    test_file = os.path.join(DATA_DIR, 'test_write.txt')
    try:
        with open(test_file, 'w') as f:
            f.write('Test write at ' + str(datetime.now()))
        debug_info["test_write_success"] = True
        os.remove(test_file)
    except Exception as e:
        debug_info["test_write_success"] = False
        debug_info["test_write_error"] = str(e)
    
    return jsonify(debug_info)

@app.route("/save-tokens", methods=['POST'])
def save_tokens():
    """Save tokens to a file for later use"""
    data = request.json
    access_token = data.get('access_token')
    refresh_token = data.get('refresh_token')
    
    if not access_token or not refresh_token:
        return jsonify({"error": "Missing tokens"}), 400
    
    token_data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'created_at': int(time.time()),
        'expires_in': 7200
    }
    
    if save_json_file(TOKENS_FILE, token_data):
        # Verify the file was saved
        saved_data = load_json_file(TOKENS_FILE)
        if saved_data:
            return jsonify({
                "success": True,
                "message": "Tokens saved successfully",
                "file_path": TOKENS_FILE,
                "verification": "File verified"
            })
    
    return jsonify({
        "error": "Failed to save tokens",
        "file_path": TOKENS_FILE,
        "data_dir": DATA_DIR
    }), 500

# Update refresh_token_endpoint to use helper functions
@app.route("/refresh-token", methods=['POST'])
def refresh_token_endpoint():
    """Refresh the access token using stored refresh token"""
    token_data = load_json_file(TOKENS_FILE)
    if not token_data:
        return jsonify({"error": "No stored tokens found"}), 404
    
    refresh_token = token_data.get('refresh_token')
    if not refresh_token:
        return jsonify({"error": "No refresh token found"}), 400
    
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    
    headers = {
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    response = requests.post(
        f"{IDENTITY_BASE_URL}/oauth/token",
        json=data,
        headers=headers,
        verify=False
    )
    
    if response.status_code == 200:
        new_token_data = response.json()
        
        # Save the new tokens
        if save_json_file(TOKENS_FILE, new_token_data):
            return jsonify({
                "success": True,
                "access_token": new_token_data.get('access_token'),
                "expires_in": new_token_data.get('expires_in')
            })
        else:
            return jsonify({
                "error": "Failed to save refreshed tokens",
                "access_token": new_token_data.get('access_token')
            }), 500
    else:
        return jsonify({
            "error": "Failed to refresh token",
            "status": response.status_code,
            "response": response.text
        }), 500

@app.route("/auto-book", methods=['POST', 'GET'])
def auto_book():
    """Automatically book using stored tokens"""
    print("\n=== AUTO-BOOK CALLED ===")
    
    # Load stored tokens FIRST
    token_data = load_json_file(TOKENS_FILE)
    if not token_data:
        return jsonify({"error": "No stored tokens. Please authenticate first."}), 404
    
    # Check if token needs refresh
    created_at = token_data.get('created_at', 0)
    expires_in = token_data.get('expires_in', 7200)
    
    if time.time() > created_at + expires_in - 300:  # 5 min buffer
        # Refresh the token
        refresh_response = refresh_token_endpoint()
        if isinstance(refresh_response, tuple) and refresh_response[1] != 200:
            return jsonify({
                "error": "Token expired and refresh failed. Please re-authenticate.",
                "hint": "Use GET /start-auth to begin manual authentication"
            }), 401
        
        # Reload token data
        token_data = load_json_file(TOKENS_FILE)
        if not token_data:
            return jsonify({"error": "Failed to reload tokens after refresh"}), 500
    
    access_token = token_data.get('access_token')
    
    # Get booking parameters ONCE
    try:
        data = request.get_json(force=True, silent=True) or {}
    except:
        data = {}
        
    venues = data.get('venues', ['DUMBO_DECK', 'NY_POOLSIDE'])
    date_time = data.get('date_time')
    party_size = data.get('party_size', 2)
    phone_number = data.get('phone_number', '7709255248')
    
    if not date_time:
        # Default to 48 hours from now at 6 PM (for testing)
        booking_date = datetime.now() + timedelta(days=2)
        date_time = booking_date.strftime('%Y-%m-%d') + 'T18:00'
    
    # Try each venue in order
    for venue_id in venues:
        print(f"\n=== Trying venue: {venue_id} ===")
        
        # Create a new request context with the venue_id
        with app.test_request_context(
            json={
                'venue_id': venue_id,
                'date_time': date_time,
                'party_size': party_size,
                'phone_number': phone_number,
                'phone_country_code': 'US'
            }
        ):
            result = book_poolside(access_token)
            
            # Check if booking was successful
            if isinstance(result, tuple):
                response_json, status_code = result
                if status_code == 200:
                    # Save success status
                    save_json_file(LAST_BOOKING_FILE, {
                        'status': f'Success: Booked {venue_id}',
                        'time': datetime.now().strftime('%Y-%m-%d %I:%M %p'),
                        'venue': venue_id,
                        'booking_time': date_time
                    })
                    return response_json
                else:
                    print(f"Failed at {venue_id}, trying next venue...")
            else:
                # Check the response for success
                try:
                    result_data = result.get_json()
                    if result_data.get('success'):
                        # Save success status
                        save_json_file(LAST_BOOKING_FILE, {
                            'status': f'Success: Booked {venue_id}',
                            'time': datetime.now().strftime('%Y-%m-%d %I:%M %p'),
                            'venue': venue_id,
                            'booking_time': date_time
                        })
                        return result
                except:
                    pass
    
    # If we get here, all venues failed
    save_json_file(LAST_BOOKING_FILE, {
        'status': f'Failed: No venues available',
        'time': datetime.now().strftime('%Y-%m-%d %I:%M %p'),
        'venues_tried': venues
    })
    
    return jsonify({
        "error": "Failed to book at any venue",
        "venues_tried": venues,
        "date_time": date_time
    }), 400

@app.route("/quick-book", methods=['POST'])
def quick_book():
    """Quick book endpoint for testing"""
    print("\n=== QUICK-BOOK ENDPOINT ===")
    
    # Load stored tokens
    try:
        with open('soho_tokens.json', 'r') as f:
            token_data = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "No stored tokens. Please authenticate first."}), 404
    
    access_token = token_data.get('access_token')
    
    # Get parameters
    data = request.json or {}
    venue_id = data.get('venue_id', 'DUMBO_DECK')
    date_time = data.get('date_time', '2025-06-03T08:00')
    party_size = data.get('party_size', 1)
    phone_number = data.get('phone_number', '7709255248')
    
    print(f"Booking {venue_id} at {date_time} for {party_size} people")
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'DigitalHouse/8.129 (com.sohohouse.houseseven; build:17190; iOS 18.5.0)'
    }
    
    # Lock the table
    lock_data = {
        "data": {
            "type": "table_locks",
            "attributes": {
                "party_size": party_size,
                "extra_attribute": "default",
                "date_time": date_time
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                }
            }
        }
    }
    
    print(f"Locking {venue_id}...")
    
    lock_response = requests.post(
        "https://api.production.sohohousedigital.com/tables/locks?include=venue,restaurant",
        json=lock_data,
        headers=headers,
        verify=False
    )
    
    if lock_response.status_code not in [200, 201]:
        return jsonify({
            "error": "Failed to lock table",
            "venue": venue_id,
            "status": lock_response.status_code,
            "response": lock_response.text
        }), lock_response.status_code
    
    lock_info = lock_response.json().get('data', {})
    lock_id = lock_info.get('id')
    
    # Create booking
    booking_data = {
        "data": {
            "type": "table_bookings",
            "attributes": {
                "date_time": date_time,
                "party_size": party_size,
                "phone": {
                    "country_code": "US",
                    "number": phone_number
                },
                "guest_notes": "",
                "terms_consent": True,
                "guest_consent": True
            },
            "relationships": {
                "restaurant": {
                    "data": {
                        "type": "restaurants",
                        "id": venue_id
                    }
                },
                "table_lock": {
                    "data": {
                        "type": "table_locks",
                        "id": lock_id
                    }
                }
            }
        }
    }
    
    booking_response = requests.post(
        "https://api.production.sohohousedigital.com/tables/table_bookings?include=venue,restaurant",
        json=booking_data,
        headers=headers,
        verify=False
    )
    
    if booking_response.status_code in [200, 201]:
        booking_info = booking_response.json().get('data', {})
        return jsonify({
            "success": True,
            "booking_id": booking_info.get('id'),
            "venue": venue_id,
            "date_time": date_time
        })
    else:
        return jsonify({
            "error": "Failed to create booking",
            "status": booking_response.status_code,
            "response": booking_response.text
        }), booking_response.status_code

# check booking status 
@app.route("/last-booking-status", methods=['GET'])
def get_last_booking_status():
    """Get the last booking status from the file"""
    booking_data = load_json_file(LAST_BOOKING_FILE)
    if booking_data:
        return jsonify(booking_data)
    else:
        return jsonify({
            "status": "No bookings yet",
            "time": "N/A",
            "venue": "N/A",
            "booking_time": "N/A"
        })

# Updated index route with booking status display
@app.route("/")
def index():
    """Simple dashboard to check bot status"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Jeannie's BookingBot</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .status { padding: 20px; margin: 20px 0; border-radius: 8px; }
            .success { background-color: #d4edda; color: #155724; }
            .error { background-color: #f8d7da; color: #721c24; }
            .warning { background-color: #fff3cd; color: #856404; }
            .info { background-color: #d1ecf1; color: #0c5460; }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; }
            .booking-form { margin: 20px 0; padding: 20px; background: #f0f0f0; border-radius: 8px; }
            input, select { padding: 8px; margin: 5px; width: 200px; }
            .last-booking { 
                margin: 20px 0; 
                padding: 20px; 
                background: #e8f4f8; 
                border-radius: 8px; 
                border: 2px solid #17a2b8;
            }
            .last-booking h3 { margin-top: 0; color: #17a2b8; }
            .booking-details { 
                display: grid; 
                grid-template-columns: auto 1fr; 
                gap: 10px; 
                margin-top: 15px;
            }
            .booking-details dt { font-weight: bold; color: #666; }
            .booking-details dd { margin: 0; }
            .pulse { animation: pulse 2s infinite; }
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
        </style>
    </head>
    <body>
        <h1>Soho House Poolside Booking Bot 🏖️</h1>
        
        <!-- Last Booking Status -->
        <div id="lastBooking" class="last-booking">
            <h3>📅 Last Booking Status</h3>
            <div id="bookingContent" class="pulse">Loading...</div>
        </div>
        
        <div id="status"></div>
        
        <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
            <h3>Complete Authentication</h3>
            <p style="font-size: 14px; color: #666;">After clicking "Start Authentication" and logging in, paste your details here. If token is expired, contact the greatest engineer in the world (Rahmin) to fix this.</p>
            <form id="authForm">
                <input type="text" id="session_id" placeholder="Session ID" style="width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 3px;" required>
                <input type="text" id="redirect_url" placeholder="Redirect URL (com.sohohouse.houseseven://...)" style="width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 3px;" required>
                <button type="submit" style="width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 5px; cursor: pointer;">Complete Authentication</button>
            </form>
            <div id="auth_result" style="margin-top: 10px;"></div>
        </div>
        
        
        <div>
            <h2>Actions</h2>
            <button onclick="checkStatus()">Check Token Status</button>
            <button onclick="refreshToken()">Refresh Token</button>
            <button onclick="startAuth()">Re-authenticate</button>
            <button onclick="checkLastBooking()">🔄 Refresh Booking Status</button>
        </div>
        
        <div id="results"></div>
        
        <script>
            async function checkLastBooking() {
                try {
                    const response = await fetch('/last-booking-status');
                    const data = await response.json();
                    
                    const bookingDiv = document.getElementById('bookingContent');
                    bookingDiv.classList.remove('pulse');
                    
                    // Check if booking was successful or failed
                    const isSuccess = data.status && data.status.includes('Success');
                    const isFailed = data.status && data.status.includes('Failed');
                    
                    // Format the booking time nicely
                    let bookingTimeFormatted = 'N/A';
                    if (data.booking_time && data.booking_time !== 'N/A') {
                        const bookingDate = new Date(data.booking_time);
                        bookingTimeFormatted = bookingDate.toLocaleString('en-US', {
                            weekday: 'long',
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric',
                            hour: 'numeric',
                            minute: '2-digit',
                            hour12: true
                        });
                    }
                    
                    if (isSuccess) {
                        bookingDiv.innerHTML = `
                            <div style="color: #155724;">
                                <strong style="font-size: 1.2em;">✅ ${data.status}</strong>
                                <dl class="booking-details">
                                    <dt>Booking Time:</dt>
                                    <dd>${bookingTimeFormatted}</dd>
                                    <dt>Venue:</dt>
                                    <dd>${data.venue === 'DUMBO_DECK' ? '🏖️ DUMBO Deck' : '🏊 NY Poolside'}</dd>
                                    <dt>Last Updated:</dt>
                                    <dd>${data.time}</dd>
                                </dl>
                            </div>
                        `;
                    } else if (isFailed) {
                        const venuesList = data.venues_tried ? data.venues_tried.join(', ') : 'N/A';
                        bookingDiv.innerHTML = `
                            <div style="color: #721c24;">
                                <strong style="font-size: 1.2em;">❌ ${data.status}</strong>
                                <dl class="booking-details">
                                    <dt>Attempted At:</dt>
                                    <dd>${data.time}</dd>
                                    <dt>Venues Tried:</dt>
                                    <dd>${venuesList}</dd>
                                </dl>
                            </div>
                        `;
                    } else {
                        bookingDiv.innerHTML = `
                            <div style="color: #666;">
                                <strong>No bookings recorded yet</strong>
                                <p style="margin-top: 10px; font-size: 0.9em;">
                                    Bookings will appear here after the cron job runs at 12:01 PM daily.
                                </p>
                            </div>
                        `;
                    }
                } catch (error) {
                    document.getElementById('bookingContent').innerHTML = 
                        `<div style="color: #721c24;">Error loading booking status: ${error.message}</div>`;
                }
            }
            
            async function checkStatus() {
                try {
                    const response = await fetch('/status');
                    const data = await response.json();
                    const statusDiv = document.getElementById('status');
                    
                    if (data.token_valid) {
                        statusDiv.className = 'status success';
                        statusDiv.innerHTML = `
                            <h3>✅ Token Valid</h3>
                            <p>Expires in: ${Math.round(data.expires_in / 60)} minutes</p>
                            <p>Auto-booking scheduled for 12:01 PM daily</p>
                        `;
                        alert('Token valid');
                    } else {
                        statusDiv.className = 'status error';
                        statusDiv.innerHTML = `
                            <h3>❌ Token Invalid</h3>
                            <p>${data.error}</p>
                            <p>Please re-authenticate</p>
                        `;
                        alert('Token invalid');
                    }
                } catch (error) {
                    console.error('Error checking status:', error);
                    document.getElementById('status').innerHTML = 
                        `<div class="status error"><h3>❌ Error</h3><p>Failed to check status: ${error.message}</p></div>`;
                }
            }
            
            async function refreshToken() {
                const response = await fetch('/refresh-token', { method: 'POST' });
                const data = await response.json();
                alert(data.success ? 'Token refreshed!' : 'Refresh failed: ' + data.error);
                checkStatus();
            }
            
            document.getElementById('authForm').addEventListener('submit', async function(event) {
                event.preventDefault();
                const sessionId = document.getElementById('session_id').value;
                const redirectUrl = document.getElementById('redirect_url').value;
                const resultDiv = document.getElementById('auth_result');
                
                resultDiv.innerHTML = '<div style="color: blue;">Processing...</div>';
                
                try {
                    const response = await fetch('/complete-auth', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            session_id: sessionId,
                            redirect_url: redirectUrl
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        resultDiv.innerHTML = '<div style="color: green;">✅ Authentication successful! Tokens saved. Reloading...</div>';
                        setTimeout(() => location.reload(), 2000);
                    } else {
                        resultDiv.innerHTML = `<div style="color: red;">❌ Error: ${data.error || 'Authentication failed'}</div>`;
                    }
                } catch (error) {
                    resultDiv.innerHTML = `<div style="color: red;">❌ Error: ${error.message}</div>`;
                }
            });
            
            async function startAuth() {
                window.location.href = '/start-auth';
            }
            
            async function bookNow() {
                const venue = document.getElementById('venue').value;
                const datetime = document.getElementById('datetime').value;
                const party = document.getElementById('party').value;
                
                const response = await fetch('/auto-book', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        venues: [venue],
                        date_time: datetime.replace('T', 'T'),
                        party_size: parseInt(party)
                    })
                });
                
                const data = await response.json();
                document.getElementById('results').innerHTML = 
                    '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                
                // Refresh the booking status after manual booking
                setTimeout(checkLastBooking, 1000);
            }
            
            // Check status and last booking on load
            checkStatus();
            checkLastBooking();
            
            // Refresh status every minute
            setInterval(checkStatus, 60000);
            
            // Refresh last booking every 30 seconds
            setInterval(checkLastBooking, 30000);
        </script>
    </body>
    </html>
    '''
@app.route("/status", methods=['GET'])
def get_status():
    """Check token status"""
    try:
        with open(TOKENS_FILE, 'r') as f:
            token_data = json.load(f)
        
        created_at = token_data.get('created_at', 0)
        expires_in = token_data.get('expires_in', 7200)
        time_left = (created_at + expires_in) - time.time()
        
        if time_left > 0:
            return jsonify({
                "token_valid": True,
                "expires_in": time_left,
                "created_at": created_at
            })
        else:
            return jsonify({
                "token_valid": False,
                "error": "Token expired"
            })
    except FileNotFoundError:
        return jsonify({
            "token_valid": False,
            "error": "No tokens found"
        })

# Add this near the end of the file, before @app.route("/scheduled-book", methods=['GET'])
def scheduled_book():
    """Endpoint for scheduled booking - can be called by Railway cron or external service"""
    # Calculate booking time (48 hours from now at 1 PM)
    booking_date = datetime.now() + timedelta(days=2)
    date_time = booking_date.strftime('%Y-%m-%d') + 'T13:00'
    
    # Make internal request to auto-book
    with app.test_request_context(
        json={
            'venues': ['DUMBO_DECK', 'NY_POOLSIDE'],
            'date_time': date_time,
            'party_size': 2,
            'phone_number': '7709255248'
        }
    ):
        result = auto_book()
        
        # Log the result
        print(f"Scheduled booking attempt at {datetime.now()}: {result}")
        
        return result

if __name__ == "__main__":
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
@app.route("/schedule-info", methods=['GET'])
def schedule_info():
    """Get information about scheduling automatic bookings"""
    return jsonify({
        "info": "Poolside booking automation",
        "rules": {
            "booking_window": "48 hours in advance",
            "slots_open": "12:00 PM daily",
            "session_duration": "3 hours",
            "available_times": "8:00 AM - 8:00 PM"
        },
        "automation_options": [
            {
                "method": "cron",
                "description": "Set up a cron job to call /auto-book at 12:00 PM daily",
                "example": "0 12 * * * curl -X POST http://127.0.0.1:5000/auto-book -H 'Content-Type: application/json' -d '{\"venue_id\":\"NY_POOLSIDE\",\"date_time\":\"2025-06-05T10:00\"}'"
            },
            {
                "method": "scheduled_task",
                "description": "Use Task Scheduler (Windows) or launchd (Mac) to run daily"
            },
            {
                "method": "python_scheduler",
                "description": "Run a Python script with schedule library"
            }
        ],
        "endpoints": {
            "/save-tokens": "Save your tokens after authentication",
            "/refresh-token": "Refresh expired access token",
            "/auto-book": "Book using saved tokens"
        }
    })

if __name__ == "__main__":
    print("\n=== Semi-Automated Soho House OAuth Flow ===")
    print("This approach bypasses reCAPTCHA by using manual browser login")
    print("\nEndpoints:")
    print("  GET  /start-auth         - Start OAuth flow (opens browser)")
    print("  POST /complete-auth      - Complete OAuth with redirect URL")
    print("  GET  /test-token/<token> - Test if token works")
    print("  POST /book-poolside/<token> - Book poolside table (TODO)")
    print("\nStarting server on http://localhost:5000")
    
    app.run(debug=True, port=5000)