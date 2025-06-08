#!/usr/bin/env python3
"""
Simple cron tasks that can be called by Railway cron
Usage: python cron_tasks.py refresh_token
       python cron_tasks.py auto_book
"""

import requests
import sys
import os
from datetime import datetime

# Get the app URL from environment
APP_URL = os.environ.get('RAILWAY_PUBLIC_DOMAIN')
if APP_URL:
    APP_URL = f"https://{APP_URL}"
else:
    print("ERROR: RAILWAY_PUBLIC_DOMAIN not set")
    sys.exit(1)

def refresh_token():
    """Refresh the authentication token"""
    print(f"[{datetime.now()}] Refreshing token...")
    try:
        response = requests.post(f"{APP_URL}/refresh-token", timeout=30)
        if response.status_code == 200:
            print("✅ Token refreshed successfully")
        else:
            print(f"❌ Failed: {response.status_code} - {response.text[:100]}")
    except Exception as e:
        print(f"❌ Error: {e}")

def auto_book():
    """Run the auto-booking process"""
    print(f"[{datetime.now()}] Running auto-book...")
    try:
        response = requests.post(
            f"{APP_URL}/auto-book",
            json={
                "venues": ["NY_POOLSIDE", "DUMBO_DECK"],
                "party_size": 2,
                "phone_number": "7709255248"
            },
            timeout=60
        )
        if response.status_code == 200:
            print("✅ Booking successful")
            print(response.json())
        else:
            print(f"❌ Failed: {response.status_code} - {response.text[:100]}")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cron_tasks.py [refresh_token|auto_book]")
        sys.exit(1)
    
    task = sys.argv[1]
    
    if task == "refresh_token":
        refresh_token()
    elif task == "auto_book":
        auto_book()
    else:
        print(f"Unknown task: {task}")
        sys.exit(1) 