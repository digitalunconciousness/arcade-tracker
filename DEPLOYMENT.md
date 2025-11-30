# Docker Deployment Guide for Proxmox

This guide covers deploying the arcade-tracker application to your Proxmox server using Docker with persistent data, auto-start, and automatic git updates.

## Overview

The deployment uses:
- **Docker** for containerization and isolation
- **Docker Compose** for orchestration
- **Volume mounts** for persistent data (database, uploads, backups)
- **Watchtower** OR **cron-based git polling** for automatic updates
- **Health checks** to ensure application reliability
- **Auto-restart** policy for resilience

## Prerequisites

1. SSH access to Proxmox server: `root@192.168.0.59`
2. Git repository URL for your project
3. Local `.env` file configured

## Quick Start

### Option 1: Automated Deployment Script

1. **Update the git repository URL** in `deploy-to-proxmox.sh`:
   ```bash
   # Edit line 8
   REPO_URL="https://github.com/YOUR_USERNAME/arcade-tracker.git"
   ```

2. **Make script executable and run**:
   ```bash
   chmod +x deploy-to-proxmox.sh
   ./deploy-to-proxmox.sh
   ```

   This script will:
   - Install Docker and Docker Compose on Proxmox
   - Clone your repository
   - Copy your database and uploads
   - Build and start containers
   - Set up auto-restart

3. **Access your application**:
   - URL: http://192.168.0.59:5000

### Option 2: Manual Deployment

1. **SSH to Proxmox server**:
   ```bash
   ssh root@192.168.0.59
   ```

2. **Install Docker** (if not already installed):
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sh get-docker.sh
   systemctl enable docker
   systemctl start docker
   ```

3. **Install Docker Compose**:
   ```bash
   curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
   ```

4. **Clone repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/arcade-tracker.git /opt/arcade-tracker
   cd /opt/arcade-tracker
   ```

5. **Create .env file** (copy from your dev machine or create new)

6. **Copy your database** (if migrating existing data):
   ```bash
   # From your local machine:
   scp arcade.db root@192.168.0.59:/opt/arcade-tracker/
   scp -r uploads/* root@192.168.0.59:/opt/arcade-tracker/uploads/
   ```

7. **Build and start**:
   ```bash
   docker-compose up -d
   ```

## Auto-Update Configuration

You have two options for automatic updates:

### Option A: Watchtower (Built-in, Default)

Watchtower is included in `docker-compose.yml` and automatically:
- Checks for updates every 5 minutes
- Rebuilds containers when code changes
- Cleans up old images
- Minimal configuration required

**Already configured!** Just commit/push to git and Watchtower handles the rest.

To adjust check interval, edit `docker-compose.yml`:
```yaml
environment:
  - WATCHTOWER_POLL_INTERVAL=300  # 300 seconds = 5 minutes
```

### Option B: Cron-based Git Polling (Alternative)

For more control or if Watchtower doesn't fit your needs:

1. **Disable Watchtower** by commenting it out in `docker-compose.yml`

2. **Setup cron job on Proxmox server**:
   ```bash
   ssh root@192.168.0.59
   cd /opt/arcade-tracker
   bash scripts/setup-auto-update-cron.sh
   ```

3. **Customize schedule** by editing the cron job:
   ```bash
   crontab -e
   ```

The script includes:
- Database backup before updates
- Health checks after update
- Automatic rollback on failure
- Detailed logging to `logs/auto-update.log`

## Data Persistence

All critical data is stored in mounted volumes (on the host filesystem):

- `./instance/` - Database files
- `./arcade.db` - Main database (root level)
- `./uploads/` - Game images
- `./static/maintenance_photos/` - Maintenance photos
- `./static/profile_pics/` - User profile pictures
- `./backups/` - Database backups
- `./logs/` - Application and update logs

**Data survives container restarts, rebuilds, and updates!**

## Common Operations

### View Logs
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose logs -f'
```

### Restart Application
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose restart'
```

### Stop Application
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose down'
```

### Start Application
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose up -d'
```

### Rebuild After Major Changes
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose down && docker-compose build --no-cache && docker-compose up -d'
```

### Manual Git Update
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && git pull && docker-compose up -d --build'
```

### Backup Database
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose exec arcade-tracker python scripts/backup_database.py backup'
```

### Access Container Shell
```bash
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose exec arcade-tracker bash'
```

### Check Container Status
```bash
ssh root@192.168.0.59 'docker ps -a | grep arcade'
```

## Updating Your Application

### Workflow with Auto-Updates Enabled

1. **Make changes on your dev machine**
2. **Test locally**: `source venv/bin/activate && python app.py`
3. **Commit and push to git**:
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin main
   ```
4. **Wait for auto-update** (5-15 minutes depending on config)
5. **Verify** at http://192.168.0.59:5000

### Manual Update Process

If you prefer manual control:

```bash
ssh root@192.168.0.59
cd /opt/arcade-tracker
git pull
docker-compose up -d --build
```

## Troubleshooting

### Container won't start
```bash
# Check logs
ssh root@192.168.0.59 'cd /opt/arcade-tracker && docker-compose logs'

# Check if port is already in use
ssh root@192.168.0.59 'netstat -tulpn | grep 5000'
```

### Database issues
```bash
# Check database file permissions
ssh root@192.168.0.59 'ls -la /opt/arcade-tracker/*.db'

# Restore from backup
ssh root@192.168.0.59 'cd /opt/arcade-tracker && python scripts/restore_database.py --interactive'
```

### Auto-update not working (Watchtower)
```bash
# Check Watchtower logs
ssh root@192.168.0.59 'docker logs arcade-watchtower'

# Force update check
ssh root@192.168.0.59 'docker restart arcade-watchtower'
```

### Auto-update not working (Cron)
```bash
# Check cron is running
ssh root@192.168.0.59 'systemctl status cron'

# Check logs
ssh root@192.168.0.59 'tail -f /opt/arcade-tracker/logs/auto-update.log'

# Manually run update script
ssh root@192.168.0.59 '/opt/arcade-tracker/scripts/auto-update.sh'
```

### Out of disk space
```bash
# Clean up old Docker images
ssh root@192.168.0.59 'docker system prune -a'

# Clean up old backups
ssh root@192.168.0.59 'cd /opt/arcade-tracker && python scripts/backup_database.py cleanup'
```

## Security Considerations

1. **Change default ports** if exposing to internet (edit `docker-compose.yml`)
2. **Add nginx reverse proxy** with HTTPS (template included in `docker-compose.yml`)
3. **Configure firewall** on Proxmox:
   ```bash
   ufw allow 5000/tcp
   ufw enable
   ```
4. **Regular backups** - automated daily backups already configured
5. **Monitor logs** for security events in `logs/security.log`

## Adding HTTPS (Optional)

Uncomment the nginx service in `docker-compose.yml` and:

1. **Create nginx.conf** with SSL configuration
2. **Generate SSL certificates** (Let's Encrypt recommended)
3. **Update ports** to use 80/443 instead of 5000

## Performance Optimization

For production workloads:

1. **Use PostgreSQL instead of SQLite** (edit DATABASE_URL in .env)
2. **Add Redis for caching** (add service to docker-compose.yml)
3. **Use Gunicorn** instead of Flask dev server (update Dockerfile CMD)
4. **Scale with multiple workers**: `docker-compose up --scale arcade-tracker=3`

## Monitoring

Set up basic monitoring:

```bash
# Watch resource usage
ssh root@192.168.0.59 'docker stats arcade-tracker'

# Monitor uptime
ssh root@192.168.0.59 'docker ps | grep arcade-tracker'
```

For production, consider:
- Prometheus + Grafana for metrics
- ELK stack for log aggregation
- Uptime monitoring service

## Backup Strategy

Automated backups are configured but verify:

1. **Daily backups** run automatically (see `scripts/setup_daily_backup.sh`)
2. **Manual backup before updates** (handled by auto-update script)
3. **Off-site backups** - periodically copy from `/opt/arcade-tracker/backups/` to your dev machine

```bash
# Sync backups to local machine
scp root@192.168.0.59:/opt/arcade-tracker/backups/*.db ./local-backups/
```

## Support

For issues:
1. Check logs: `docker-compose logs`
2. Verify container health: `docker ps`
3. Review update logs: `logs/auto-update.log`
4. Check database: `python check_db_schema.py`
