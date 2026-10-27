# Cloud Storage Setup Guide

## 🌥️ Free Cloud Storage Options

### 1. AWS S3 Free Tier (RECOMMENDED)
- **5GB free storage** for 12 months
- **20,000 GET requests** + 2,000 PUT requests/month
- Perfect for maintenance photos

#### Setup Steps:
1. Create AWS account at https://aws.amazon.com
2. Go to S3 service and create a bucket:
   - Bucket name: `your-arcade-photos` (must be globally unique)
   - Region: `us-east-1` (or closest to you)
   - Enable public read access for photos
3. Create IAM user with S3 permissions:
   - Go to IAM → Users → Create User
   - Attach policy: `AmazonS3FullAccess`
   - Save Access Key ID and Secret Access Key

#### Environment Variables:
```bash
export USE_CLOUD_STORAGE=true
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_BUCKET_NAME="your-arcade-photos"
export AWS_REGION="us-east-1"
```

### 2. Google Cloud Storage (Alternative)
- **5GB free storage** always
- Easy setup but requires payment method

### 3. Cloudflare R2 (Alternative)
- **10GB free storage** always
- S3-compatible API

## 📱 Mobile Upload Options

### Option A: Direct Web Upload (Current)
- Use tablet/phone browser to access your app
- Go to maintenance record → Upload Photos
- Select photos from camera roll or take new ones

### Option B: Cloud Sync Folder (Future Enhancement)
Set up automatic sync from phone to cloud:
1. **Google Drive/Dropbox**: Auto-upload photos from phone
2. **Webhook Integration**: Automatically import new photos to maintenance records
3. **QR Code**: Generate QR codes linking photos to specific maintenance orders

### Option C: Mobile App (Advanced)
- React Native or Flutter app
- Direct camera integration
- Offline support with sync

## 🔧 Setup Instructions

### 1. Install Dependencies
```bash
pip install boto3  # For AWS S3 support
```

### 2. Configure Environment
Create `.env` file in your arcade-tracker directory:
```bash
# Cloud Storage Configuration
USE_CLOUD_STORAGE=true
AWS_ACCESS_KEY_ID=your-key-here
AWS_SECRET_ACCESS_KEY=your-secret-here
AWS_BUCKET_NAME=arcade-tracker-photos
AWS_REGION=us-east-1
```

### 3. Load Environment Variables
Add to your startup script:
```bash
source .env
python app.py
```

### 4. Test Upload
1. Create a maintenance record
2. Upload a test photo
3. Check your S3 bucket for the uploaded file
4. Verify photos display in the maintenance view

## 📊 Storage Monitoring

The app includes built-in storage monitoring:
- View usage at `/admin/storage` (admin users only)
- Automatic compression reduces file sizes by ~90%
- Photos stored permanently in cloud
- Local copies automatically cleaned up

## 💰 Cost Estimates

### AWS S3 (assuming 100 photos/month, 2MB each compressed):
- **Storage**: ~200MB/month = $0.05/month
- **Requests**: ~100 PUT = $0.001/month
- **Data Transfer**: Free for downloads under 100GB
- **Total**: ~$0.60/year

### Backup Strategy:
- Cloud storage = permanent archive
- Local storage = temporary cache
- Database = photo filenames only

This setup ensures your maintenance photos are preserved forever while keeping local storage minimal!