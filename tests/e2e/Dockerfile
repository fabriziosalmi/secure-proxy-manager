# Playwright test runner
# Uses the official Microsoft image which bundles Chromium, Firefox, WebKit
# and all OS-level dependencies needed to run them headlessly.
FROM mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e

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
