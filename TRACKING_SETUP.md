# Shipment Tracking Setup Guide

This guide explains how to set up automatic shipment tracking using the EasyPost API for inventory requests.

## Overview

The arcade tracker now supports automatic tracking updates for inventory shipments through the EasyPost API. This feature:
- Automatically fetches tracking status from carriers (USPS, UPS, FedEx, etc.)
- Updates estimated delivery dates
- Maintains complete audit history
- Works with a manual refresh button (no automatic polling)

## Setup Instructions

### 1. Sign up for EasyPost

1. Go to [https://www.easypost.com/signup](https://www.easypost.com/signup)
2. Create a free account
3. Navigate to your API Keys page
4. Copy your **Test API Key** (starts with `EZTKTEST_`) or **Production API Key** (starts with `EZAK_`)

### 2. Add API Key to Environment

Add the following line to your `.env` file:

```bash
EASYPOST_API_KEY=your-api-key-here
```

**Example:**
```bash
EASYPOST_API_KEY=EZTKTEST_abc123def456...
```

### 3. Restart the Application

After adding the API key, restart your Flask application:

```bash
python app.py
```

## Usage

### For Managers/Admins

1. Go to an inventory request detail page
2. Ensure the request has a **tracking number** entered
3. Click the **🔄 Update Tracking** button
4. The system will fetch the latest status from the carrier

### Tracking Information Displayed

Once updated, you'll see:
- **Current status**: in_transit, out_for_delivery, delivered, etc.
- **Carrier**: USPS, UPS, FedEx, etc.
- **Last update time**: When tracking was last refreshed
- **Estimated delivery date**: Auto-updated if carrier provides it

### Status Meanings

| Status | Meaning |
|--------|---------|
| `pre_transit` | Label created, waiting for carrier pickup |
| `in_transit` | Package is being shipped |
| `out_for_delivery` | Package is out for delivery today |
| `delivered` | Package has been delivered |
| `available_for_pickup` | Package ready for pickup |
| `return_to_sender` | Package being returned |
| `failure` | Delivery issue occurred |

## API Limits

### Free Tier (Test Mode)
- **100 tracking requests per month**
- Perfect for testing and small operations

### Paid Plans
- Start at **$0.05 per tracking request**
- Or monthly plans starting at $9/month for 100 requests
- See [EasyPost Pricing](https://www.easypost.com/pricing) for details

## Supported Carriers

EasyPost supports 100+ carriers including:
- ✅ USPS
- ✅ UPS
- ✅ FedEx
- ✅ DHL
- ✅ Canada Post
- ✅ And many more...

## Troubleshooting

### "Tracking API not configured" Error
**Solution:** Add `EASYPOST_API_KEY` to your `.env` file and restart the app.

### "EasyPost library not installed" Error
**Solution:** Run `pip install easypost` or `pip install -r requirements.txt`

### "Invalid tracking number" Error
**Causes:**
- Tracking number not yet in carrier's system (try again in a few hours)
- Incorrect tracking number entered
- Carrier not supported

### Track Manually Without API

If you don't want to use the API, you can still manually update request information in the update modal. The tracking number field supports copy-paste for manual lookup.

## Security Notes

- ⚠️ **Never commit** your API key to version control
- ⚠️ Use **Test keys** for development
- ⚠️ Use **Production keys** only in production
- ⚠️ Keep your `.env` file in `.gitignore`

## Optional: Carrier Detection

The system defaults to USPS if no carrier is specified. You can manually set the carrier when entering tracking info in the request update form to improve accuracy.

Common carrier codes:
- `USPS` - US Postal Service
- `UPS` - United Parcel Service
- `FedEx` - Federal Express
- `DHLExpress` - DHL Express

## Disabling Tracking API

If you don't want to use the API feature:
1. Simply don't add the `EASYPOST_API_KEY` to your `.env`
2. The "Update Tracking" button will show a message that API is not configured
3. All other inventory request features continue to work normally
