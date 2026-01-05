#!/bin/bash
# Validation script to verify the deployment fixes

echo "=================================================="
echo "Deployment Fixes Validation Script"
echo "=================================================="
echo ""

PASS=0
FAIL=0

# Function to check if a file exists
check_file() {
    if [ -f "$1" ]; then
        echo "✓ PASS: $1 exists"
        PASS=$((PASS + 1))
    else
        echo "✗ FAIL: $1 does not exist"
        FAIL=$((FAIL + 1))
    fi
}

# Function to check if a directory exists
check_dir() {
    if [ -d "$1" ]; then
        echo "✓ PASS: Directory $1 exists"
        PASS=$((PASS + 1))
    else
        echo "✗ FAIL: Directory $1 does not exist"
        FAIL=$((FAIL + 1))
    fi
}

# Function to check if a string exists in a file
check_content() {
    if grep -q "$2" "$1"; then
        echo "✓ PASS: $1 contains '$2'"
        PASS=$((PASS + 1))
    else
        echo "✗ FAIL: $1 does not contain '$2'"
        FAIL=$((FAIL + 1))
    fi
}

echo "Checking required files..."
echo "----------------------------"
check_file ".env.example"
check_file "init.sh"
check_file "DEPLOYMENT.md"
check_file "logs/.gitkeep"

echo ""
echo "Checking required directories..."
echo "--------------------------------"
check_dir "config"
check_dir "data"
check_dir "logs"

echo ""
echo "Checking .env.example content..."
echo "--------------------------------"
check_content ".env.example" "BASIC_AUTH_USERNAME"
check_content ".env.example" "BASIC_AUTH_PASSWORD"
check_content ".env.example" "SECRET_KEY"

echo ""
echo "Checking docker-compose.yml has default values..."
echo "-------------------------------------------------"
check_content "docker-compose.yml" "BASIC_AUTH_USERNAME:-admin"
check_content "docker-compose.yml" "BASIC_AUTH_PASSWORD:-admin"

echo ""
echo "Checking UI Dockerfile has proper directory creation..."
echo "-------------------------------------------------------"
check_content "ui/Dockerfile" "mkdir -p /logs /data /config"
check_content "ui/Dockerfile" "chown -R appuser:appuser"

echo ""
echo "Checking UI app.py has default credential handling..."
echo "-----------------------------------------------------"
check_content "ui/app.py" "os.environ.get('BASIC_AUTH_USERNAME', 'admin')"
check_content "ui/app.py" "os.environ.get('BASIC_AUTH_PASSWORD', 'admin')"

echo ""
echo "Checking .gitignore allows logs directory..."
echo "--------------------------------------------"
check_content ".gitignore" "!logs/.gitkeep"

echo ""
echo "Checking README has deployment guide reference..."
echo "------------------------------------------------"
check_content "README.md" "DEPLOYMENT.md"
check_content "README.md" "init.sh"

echo ""
echo "Checking init.sh is executable..."
echo "---------------------------------"
if [ -x "init.sh" ]; then
    echo "✓ PASS: init.sh is executable"
    PASS=$((PASS + 1))
else
    echo "✗ FAIL: init.sh is not executable"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=================================================="
echo "Validation Summary"
echo "=================================================="
echo "PASSED: $PASS"
echo "FAILED: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "✓ All checks passed! The deployment fixes are complete."
    exit 0
else
    echo "✗ Some checks failed. Please review the output above."
    exit 1
fi
