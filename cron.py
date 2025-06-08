import requests
import schedule
import time
import os
from datetime import datetime

# Get the app URL from environment or use default
APP_URL = os.environ.get('RAILWAY_PUBLIC_DOMAIN')
if APP_URL:
    APP_URL = f"https://{APP_URL}"
else:
    # Fallback for local testing
    APP_URL = "http://127.0.0.1:5000"

print(f"Cron job starting... Will use URL: {APP_URL}")

def refresh_token_job():
    """Test job that refreshes the token"""
    try:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running refresh token job...")
        
        response = requests.post(
            f"{APP_URL}/refresh-token",
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Token refreshed successfully!")
            print(f"   New token expires in: {data.get('expires_in', 'unknown')} seconds")
        else:
            print(f"❌ Failed to refresh token: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def auto_book_job():
    """Main job that runs the auto-booking at 12:00 PM"""
    try:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running auto-book job...")
        
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
            data = response.json()
            print(f"✅ Booking successful!")
            print(f"   Booking ID: {data.get('booking_id', 'unknown')}")
        else:
            print(f"❌ Booking failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

# Schedule the jobs
# Test: Refresh token every 5 minutes
schedule.every(5).minutes.do(refresh_token_job)

# Production: Auto-book daily at 12:00 PM EST
schedule.every().day.at("12:00").do(auto_book_job)

# For testing: Run refresh token immediately on startup
print("Running initial token refresh...")
refresh_token_job()

# Main loop
print("\n📅 Scheduled jobs:")
print("  - Token refresh: Every 5 minutes")
print("  - Auto booking: Daily at 12:01 PM")
print("\nCron job is running... Press Ctrl+C to stop\n")

while True:
    schedule.run_pending()
    time.sleep(1)
