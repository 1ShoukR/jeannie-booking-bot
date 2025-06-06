# jeannie-booking-bot 🏖️

## This is a booking bot made for SOHO House poolside booking

An automated bot that books poolside beds at Soho House locations 48 hours in advance, ensuring you never miss out on prime poolside spots.

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Automated Booking](#automated-booking)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Technical Details](#technical-details)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This bit essneitally just books poolside beds at SOHO House NY and 

### How It Works
A corn job hits the `/auto-book` route for the application to automatically book 1:30 PM slots

## ✨ Features

- 🤖 Automated daily bookings 48 hours in advance
- 🔄 Automatic token refresh
- 📱 SMS confirmations from Soho House
- 🏖️ Multiple venue support with fallback options
- 📊 Web dashboard for monitoring
- 💾 Persistent token storage
- ⏰ Configurable booking times

## 📦 Prerequisites

- Python 3.8+
- Railway account (for deployment)
- Soho House membership
- Soho House mobile app credentials

## 🚀 Installation

### Local Development

```bash
# Clone the repository
git clone https://github.com/yourusername/jeannie-booking-bot.git
cd jeannie-booking-bot

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py