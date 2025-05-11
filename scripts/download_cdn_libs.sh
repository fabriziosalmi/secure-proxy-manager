#!/bin/bash
# Script to download all third-party libraries locally
# This ensures we're not dependent on external CDNs

# Set the static directory
STATIC_DIR="../ui/static"
JS_DIR="$STATIC_DIR/js"
CSS_DIR="$STATIC_DIR/css"
FONTS_DIR="$STATIC_DIR/fonts"

# Create directories if they don't exist
mkdir -p $JS_DIR
mkdir -p $CSS_DIR
mkdir -p $FONTS_DIR

echo "Downloading third-party libraries..."

# JavaScript libraries
echo "Downloading JavaScript libraries..."

# Bootstrap Bundle with Popper (already exists, but updating to latest)
echo "Downloading Bootstrap Bundle..."
curl -s https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js -o $JS_DIR/bootstrap.bundle.min.js

# jQuery (already exists, but updating to latest)
echo "Downloading jQuery..."
curl -s https://code.jquery.com/jquery-3.6.0.min.js -o $JS_DIR/jquery.min.js

# Chart.js (already exists, but updating to latest)
echo "Downloading Chart.js..."
curl -s https://cdn.jsdelivr.net/npm/chart.js@3.7.0/dist/chart.min.js -o $JS_DIR/chart.min.js

# CSS libraries
echo "Downloading CSS libraries..."

# Bootstrap CSS (already exists, but updating to latest)
echo "Downloading Bootstrap CSS..."
curl -s https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css -o $CSS_DIR/bootstrap.min.css

# Font Awesome CSS (might not exist locally with this exact file name)
echo "Downloading Font Awesome CSS..."
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css -o $CSS_DIR/fontawesome.min.css

# Download Font Awesome webfonts
echo "Downloading Font Awesome webfonts..."
mkdir -p $FONTS_DIR/fontawesome
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-solid-900.woff2 -o $FONTS_DIR/fontawesome/fa-solid-900.woff2
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-solid-900.ttf -o $FONTS_DIR/fontawesome/fa-solid-900.ttf
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-regular-400.woff2 -o $FONTS_DIR/fontawesome/fa-regular-400.woff2
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-regular-400.ttf -o $FONTS_DIR/fontawesome/fa-regular-400.ttf
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-brands-400.woff2 -o $FONTS_DIR/fontawesome/fa-brands-400.woff2
curl -s https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/fa-brands-400.ttf -o $FONTS_DIR/fontawesome/fa-brands-400.ttf

# Update fontawesome CSS paths to point to local files
echo "Updating Font Awesome CSS paths..."
# Replace both absolute and relative webfont paths
sed -i.bak 's|https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/webfonts/|/static/fonts/fontawesome/|g' $CSS_DIR/fontawesome.min.css
sed -i.bak 's|../webfonts/|/static/fonts/fontawesome/|g' $CSS_DIR/fontawesome.min.css
rm $CSS_DIR/fontawesome.min.css.bak

echo "All libraries have been downloaded successfully!"
echo "Remember to run this script again when updating to newer versions of libraries."
