#!/bin/bash
# Secure Proxy Manager - Initialization Script
# This script prepares the environment for first-time deployment

set -e  # Exit on error

echo "=================================================="
echo "Secure Proxy Manager - Initialization"
echo "=================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo "→ $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi
print_success "Docker is installed"

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi
print_success "Docker Compose is installed"

# Check if Docker daemon is running
if ! docker ps &> /dev/null; then
    print_error "Docker daemon is not running. Please start Docker first."
    exit 1
fi
print_success "Docker daemon is running"

echo ""
print_info "Creating required directories..."

# Create directories if they don't exist
mkdir -p config data logs

print_success "Created config directory"
print_success "Created data directory"
print_success "Created logs directory"

# Set proper permissions (ensure they're writable)
chmod 755 config data logs

print_success "Set directory permissions"

# Create empty blacklist files if they don't exist
if [ ! -f config/ip_blacklist.txt ]; then
    touch config/ip_blacklist.txt
    print_success "Created config/ip_blacklist.txt"
else
    print_info "config/ip_blacklist.txt already exists"
fi

if [ ! -f config/domain_blacklist.txt ]; then
    touch config/domain_blacklist.txt
    print_success "Created config/domain_blacklist.txt"
else
    print_info "config/domain_blacklist.txt already exists"
fi

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found"
    print_info "Creating .env file from .env.example..."
    
    if [ -f .env.example ]; then
        cp .env.example .env
        print_success "Created .env file from .env.example"
        echo ""
        print_error "=============================================="
        print_error "SECURITY WARNING: Default Credentials in Use"
        print_error "=============================================="
        print_warning "The .env file contains default credentials:"
        print_warning "  Username: admin"
        print_warning "  Password: admin"
        echo ""
        print_warning "These MUST be changed before production deployment!"
        print_warning "Edit .env file now or press Ctrl+C to exit."
        echo ""
        read -p "Press Enter to continue with default credentials (NOT RECOMMENDED) or Ctrl+C to exit and edit .env now..."
    else
        print_error ".env.example file not found. Creating minimal .env file..."
        cat > .env << 'EOF'
# Minimal environment configuration
# WARNING: This file was auto-generated with INSECURE default credentials!
# CHANGE THESE IMMEDIATELY before deploying to production!

BASIC_AUTH_USERNAME=admin
BASIC_AUTH_PASSWORD=admin
SECRET_KEY=
FLASK_ENV=production
BACKEND_URL=http://backend:5000
REQUEST_TIMEOUT=30
MAX_RETRIES=5
BACKOFF_FACTOR=1.0
RETRY_WAIT_AFTER_STARTUP=10
PROXY_HOST=proxy
PROXY_PORT=3128
PROXY_CONTAINER_NAME=secure-proxy-proxy-1
EOF
        print_success "Created minimal .env file with default values"
        echo ""
        print_error "=============================================="
        print_error "SECURITY WARNING: Default Credentials in Use"
        print_error "=============================================="
        print_warning "The .env file contains INSECURE default credentials:"
        print_warning "  Username: admin"
        print_warning "  Password: admin"
        echo ""
        print_warning "These MUST be changed before production deployment!"
        print_warning "Edit .env file now: nano .env"
        echo ""
    fi
else
    print_success ".env file already exists"
    
    # Check if credentials are set to defaults (exact match on uncommented lines)
    if grep -q "^BASIC_AUTH_USERNAME=admin$" .env && grep -q "^BASIC_AUTH_PASSWORD=admin$" .env; then
        echo ""
        print_warning "WARNING: You are using default credentials (admin/admin)"
        print_warning "It is strongly recommended to change these in the .env file"
    fi
fi

echo ""
print_info "Checking Docker images..."

# Check if we need to build images
if docker images | grep -q "secure-proxy-manager"; then
    print_info "Docker images exist. They will be rebuilt if docker-compose.yml has changed."
else
    print_info "Docker images will be built on first startup."
fi

echo ""
echo "=================================================="
print_success "Initialization complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Review and edit the .env file to customize your deployment:"
echo "   ${YELLOW}nano .env${NC}  or  ${YELLOW}vi .env${NC}"
echo ""
echo "2. Start the application:"
echo "   ${GREEN}docker-compose up -d${NC}"
echo ""
echo "3. Check the logs to ensure everything started correctly:"
echo "   ${GREEN}docker-compose logs -f${NC}"
echo ""
echo "4. Access the web interface:"
echo "   ${GREEN}http://localhost:8011${NC}"
echo "   Default credentials: admin / admin (change these!)"
echo ""
echo "5. Configure your proxy client to use:"
echo "   Host: ${GREEN}localhost${NC} (or your server IP)"
echo "   Port: ${GREEN}3128${NC}"
echo ""
echo "For more information, see README.md or DEPLOYMENT.md"
echo ""
