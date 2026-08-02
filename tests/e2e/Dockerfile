# Playwright test runner
# Uses the official Microsoft image which bundles Chromium, Firefox, WebKit
# and all OS-level dependencies needed to run them headlessly.
FROM mcr.microsoft.com/playwright:v1.62.0-noble@sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07

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
