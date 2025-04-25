#!/bin/bash
# Squid Proxy Service Management Script

set -e

# Configuration
SQUID_SERVICE="squid"
CONFIG_FILE="/etc/squid/squid.conf"
LOG_FILE="/var/log/squid/access.log"
CACHE_DIR="/var/cache/squid"
PID_FILE="/var/run/squid.pid"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}This script must be run as root${NC}" >&2
        exit 1
    fi
}

# Function to start the Squid service
start_service() {
    echo -e "${YELLOW}Starting Squid proxy service...${NC}"
    if systemctl is-active --quiet $SQUID_SERVICE; then
        echo -e "${GREEN}Squid is already running${NC}"
    else
        systemctl start $SQUID_SERVICE
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Squid proxy service started successfully${NC}"
        else
            echo -e "${RED}Failed to start Squid proxy service${NC}"
            exit 1
        fi
    fi
}

# Function to stop the Squid service
stop_service() {
    echo -e "${YELLOW}Stopping Squid proxy service...${NC}"
    if systemctl is-active --quiet $SQUID_SERVICE; then
        systemctl stop $SQUID_SERVICE
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Squid proxy service stopped successfully${NC}"
        else
            echo -e "${RED}Failed to stop Squid proxy service${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}Squid is not running${NC}"
    fi
}

# Function to restart the Squid service
restart_service() {
    echo -e "${YELLOW}Restarting Squid proxy service...${NC}"
    systemctl restart $SQUID_SERVICE
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Squid proxy service restarted successfully${NC}"
    else
        echo -e "${RED}Failed to restart Squid proxy service${NC}"
        exit 1
    fi
}

# Function to check the status of the Squid service
status_service() {
    echo -e "${YELLOW}Checking Squid proxy service status...${NC}"
    if systemctl is-active --quiet $SQUID_SERVICE; then
        echo -e "${GREEN}Squid proxy is running${NC}"
        systemctl status $SQUID_SERVICE | grep "Active:"
    else
        echo -e "${RED}Squid proxy is not running${NC}"
    fi
}

# Function to validate the Squid configuration
validate_config() {
    echo -e "${YELLOW}Validating Squid configuration...${NC}"
    squid -k parse -f $CONFIG_FILE
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Configuration is valid${NC}"
    else
        echo -e "${RED}Configuration is invalid${NC}"
        exit 1
    fi
}

# Function to display recent logs
show_logs() {
    echo -e "${YELLOW}Showing recent logs (last 50 lines):${NC}"
    if [ -f "$LOG_FILE" ]; then
        tail -n 50 $LOG_FILE
    else
        echo -e "${RED}Log file not found: $LOG_FILE${NC}"
    fi
}

# Function to clear cache
clear_cache() {
    echo -e "${YELLOW}Clearing Squid cache...${NC}"
    stop_service
    echo -e "${YELLOW}Removing cache files...${NC}"
    rm -rf $CACHE_DIR/*
    echo -e "${YELLOW}Initializing cache directory...${NC}"
    squid -z
    start_service
    echo -e "${GREEN}Cache cleared successfully${NC}"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [option]"
    echo "Options:"
    echo "  start      Start Squid proxy service"
    echo "  stop       Stop Squid proxy service"
    echo "  restart    Restart Squid proxy service"
    echo "  status     Show Squid proxy service status"
    echo "  validate   Validate Squid configuration"
    echo "  logs       Show recent logs"
    echo "  clear      Clear Squid cache"
    echo "  help       Show this help message"
}

# Main script execution
check_root

case "$1" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        status_service
        ;;
    validate)
        validate_config
        ;;
    logs)
        show_logs
        ;;
    clear)
        clear_cache
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        echo -e "${RED}Invalid option: $1${NC}"
        show_usage
        exit 1
        ;;
esac

exit 0