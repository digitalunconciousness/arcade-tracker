#!/bin/bash
# Deploy arcade-tracker to Proxmox server

set -e

PROXMOX_HOST="root@192.168.0.59"
DEPLOY_PATH="/opt/arcade-tracker"
REPO_URL="https://github.com/digitalunconciousness/arcade-tracker.git"

echo "🚀 Deploying arcade-tracker to Proxmox server..."

# Step 1: Check if server is reachable
echo "📡 Checking connection to Proxmox server..."
if ! ssh -o ConnectTimeout=5 "$PROXMOX_HOST" "echo Connected"; then
    echo "❌ Cannot connect to Proxmox server at $PROXMOX_HOST"
    exit 1
fi

# Step 2: Install Docker and Docker Compose on Proxmox if needed
echo "🐳 Ensuring Docker is installed..."
ssh "$PROXMOX_HOST" << 'ENDSSH'
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

docker --version
docker compose version
ENDSSH

# Step 3: Create deployment directory
echo "📁 Creating deployment directory..."
ssh "$PROXMOX_HOST" "mkdir -p $DEPLOY_PATH"

# Step 4: Clone or update repository
echo "📦 Cloning/updating repository..."
ssh "$PROXMOX_HOST" << ENDSSH
if [ -d "$DEPLOY_PATH/.git" ]; then
    echo "Repository exists, pulling latest changes..."
    cd $DEPLOY_PATH
    git pull
else
    echo "Cloning repository..."
    git clone $REPO_URL $DEPLOY_PATH
fi
ENDSSH

# Step 5: Copy Docker files
echo "🐳 Copying Docker files..."
if [ ! -f docker-compose.yml ]; then
    echo "❌ docker-compose.yml not found locally"
    exit 1
fi
if [ ! -f Dockerfile ]; then
    echo "❌ Dockerfile not found locally"
    exit 1
fi
if [ ! -f requirements.txt ]; then
    echo "❌ requirements.txt not found locally"
    exit 1
fi
scp docker-compose.yml Dockerfile requirements.txt "$PROXMOX_HOST:$DEPLOY_PATH/"
if [ -f .dockerignore ]; then
    scp .dockerignore "$PROXMOX_HOST:$DEPLOY_PATH/"
fi

# Step 6: Copy .env file if it exists locally
if [ -f .env ]; then
    echo "📋 Copying .env file..."
    scp .env "$PROXMOX_HOST:$DEPLOY_PATH/.env"
else
    echo "⚠️  No .env file found locally. You'll need to create one on the server."
fi

# Step 7: Create necessary directories on server
echo "📂 Creating data directories..."
ssh "$PROXMOX_HOST" << ENDSSH
cd $DEPLOY_PATH
mkdir -p instance uploads static/maintenance_photos static/profile_pics backups logs
ENDSSH

# Step 8: Copy existing database if it exists
if [ -f arcade.db ]; then
    echo "💾 Copying existing database..."
    scp arcade.db "$PROXMOX_HOST:$DEPLOY_PATH/arcade.db"
fi

if [ -f instance/arcade.db ]; then
    echo "💾 Copying existing database from instance folder..."
    scp instance/arcade.db "$PROXMOX_HOST:$DEPLOY_PATH/instance/arcade.db"
fi

# Step 9: Copy existing uploads if they exist
if [ -d uploads ] && [ "$(ls -A uploads)" ]; then
    echo "📸 Copying existing uploads..."
    scp -r uploads/* "$PROXMOX_HOST:$DEPLOY_PATH/uploads/"
fi

# Step 10: Build and start containers
echo "🏗️  Building and starting Docker containers..."
ssh "$PROXMOX_HOST" << ENDSSH
cd $DEPLOY_PATH
docker compose -f docker-compose.yml down
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
ENDSSH

# Step 11: Wait for container to be healthy
echo "⏳ Waiting for container to be healthy..."
sleep 10
ssh "$PROXMOX_HOST" "docker ps -a | grep arcade-tracker"

# Step 12: Show logs
echo "📏 Recent logs:"
ssh "$PROXMOX_HOST" "cd $DEPLOY_PATH && docker compose -f docker-compose.yml logs --tail=20"

echo ""
echo "✅ Deployment complete!"
echo "🌐 Application should be accessible at: http://192.168.0.59:5000"
echo ""
echo "Useful commands:"
echo "  ssh $PROXMOX_HOST 'cd $DEPLOY_PATH && docker compose -f docker-compose.yml logs -f'  # View logs"
echo "  ssh $PROXMOX_HOST 'cd $DEPLOY_PATH && docker compose -f docker-compose.yml restart'  # Restart"
echo "  ssh $PROXMOX_HOST 'cd $DEPLOY_PATH && docker compose -f docker-compose.yml down'     # Stop"
echo "  ssh $PROXMOX_HOST 'cd $DEPLOY_PATH && docker compose -f docker-compose.yml up -d'    # Start"
