# Playwright test runner
# Uses the official Microsoft image which bundles Chromium, Firefox, WebKit
# and all OS-level dependencies needed to run them headlessly.
FROM mcr.microsoft.com/playwright:v1.64.0-noble@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f

WORKDIR /tests

# Install Node deps first (cached layer)
COPY package*.json ./
RUN npm ci

# Copy test source
COPY . .

# Results volume — mounted by docker-compose so reports survive container exit
VOLUME ["/test-results"]

# Default: run the full suite; override CMD to run a subset
CMD ["npx", "playwright", "test", "--reporter=list"]
